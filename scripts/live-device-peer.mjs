#!/usr/bin/env node

// Bounded, per-host controller for live-device qualification. This is not a
// network service: its only inputs are local files staged by the coordinator,
// and its only network connection is the daemon's production local JSONL IPC.

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  createReadStream,
  existsSync,
  openSync,
} from "node:fs";
import {
  access,
  mkdir,
  open,
  readFile,
  realpath,
  stat,
} from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const LIMITS = Object.freeze({
  configBytes: 8 * 1024 * 1024,
  grantBytes: 64 * 1024,
  commandBytes: 1024 * 1024,
  frameBytes: 8 * 1024 * 1024,
  queuedFrames: 256,
  commands: 4096,
  commandIdBytes: 256,
  subscriptions: 64,
  events: 100_000,
  outputBytes: 256 * 1024 * 1024,
  outputRecordBytes: 64 * 1024 * 1024,
  pollMs: 100,
  readyMs: 30_000,
  rpcMs: 15_000,
  shutdownMs: 10_000,
  maxDurationMs: 24 * 60 * 60 * 1000,
});

const FACT_ACTIONS = new Set(["role-stream", "identity", "converge", "export"]);
const PAYLOAD_ACTIONS = new Set([
  "echo_listen",
  "echo_run",
  "relay_echo_listen",
  "relay_echo_run",
]);
const STREAM_MODE_OPS = new Set(["events_subscribe", "trace_subscribe", "realtime_pipe"]);
const SENSITIVE_KEY = /(?:capability|password|secret|token|mfa(?:_|$)|^code$|^handle$)/i;
const HERE = path.dirname(fileURLToPath(import.meta.url));

export class ControllerError extends Error {
  constructor(message, kind = "failed", cause = undefined) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "ControllerError";
    this.kind = kind;
  }
}

export function monoMs() {
  return Number(process.hrtime.bigint()) / 1_000_000;
}

function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new ControllerError("controller deadline reached"));
      return;
    }
    const onDone = () => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    };
    const timer = setTimeout(onDone, ms);
    timer.unref?.();
    const onAbort = () => {
      clearTimeout(timer);
      reject(new ControllerError("controller deadline reached"));
    };
    signal?.addEventListener(
      "abort",
      onAbort,
      { once: true },
    );
  });
}

function remainingMs(deadlineMs, requestedMs) {
  const remaining = Math.floor(deadlineMs - monoMs());
  if (remaining <= 0) throw new ControllerError("controller deadline reached");
  const requested = requestedMs === undefined ? LIMITS.rpcMs : requestedMs;
  if (!Number.isSafeInteger(requested) || requested <= 0) {
    throw new ControllerError("timeoutMs must be a positive safe integer");
  }
  return Math.max(1, Math.min(remaining, requested));
}

function withTimeout(promise, timeoutMs, message, signal) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      fn(value);
    };
    const timer = setTimeout(
      () => finish(reject, new ControllerError(message)),
      timeoutMs,
    );
    const onAbort = () =>
      finish(reject, new ControllerError("controller deadline reached"));
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) onAbort();
    Promise.resolve(promise).then(
      (value) => finish(resolve, value),
      (error) => finish(reject, error),
    );
  });
}

export function sanitizeEvidence(value, seen = new WeakSet()) {
  if (value === null || typeof value !== "object") return value;
  if (seen.has(value)) throw new ControllerError("cyclic evidence is not serializable");
  seen.add(value);
  try {
    if (Array.isArray(value)) return value.map((entry) => sanitizeEvidence(entry, seen));
    const result = {};
    for (const [key, entry] of Object.entries(value)) {
      result[key] = SENSITIVE_KEY.test(key) ? "[redacted]" : sanitizeEvidence(entry, seen);
    }
    return result;
  } finally {
    seen.delete(value);
  }
}

function errorEvidence(error) {
  const result = {
    name: typeof error?.name === "string" ? error.name : "Error",
    message: typeof error?.message === "string" ? error.message : String(error),
  };
  if (typeof error?.code === "string" || typeof error?.code === "number") {
    result.code = error.code;
  }
  if (typeof error?.kind === "string") result.kind = error.kind;
  if (error?.result !== undefined) result.partial = sanitizeEvidence(error.result);
  return result;
}

export function commandErrorStatus(error) {
  if (error?.kind === "outcome_unknown") return "outcome_unknown";
  if (typeof error?.category === "string" && /outcome_unknown/.test(error.category)) {
    return "outcome_unknown";
  }
  if (Number(error?.result?.outcomeUnknown) > 0) return "outcome_unknown";
  const message = typeof error?.message === "string" ? error.message : "";
  return /outcome(?:_| )unknown|commit state requires reconciliation|stopped without retry/i.test(
    message,
  )
    ? "outcome_unknown"
    : "failed";
}

function hasOutcomeUnknown(value, seen = new WeakSet()) {
  if (value === null || typeof value !== "object") return false;
  if (seen.has(value)) return false;
  seen.add(value);
  try {
    for (const [key, entry] of Object.entries(value)) {
      const normalized = key.replaceAll("_", "").toLowerCase();
      if (
        (normalized.includes("outcomeunknown") || normalized.includes("sendoutcomeunknown")) &&
        Number(entry) > 0
      ) {
        return true;
      }
      if (
        ["outcome", "workloadoutcome", "status", "category", "closeoutcome"].includes(
          normalized,
        ) &&
        typeof entry === "string" &&
        /outcome_unknown|unconfirmed/i.test(entry)
      ) {
        return true;
      }
      if (entry && typeof entry === "object" && hasOutcomeUnknown(entry, seen)) return true;
    }
    return false;
  } finally {
    seen.delete(value);
  }
}

function cleanPayloadResult(result) {
  if (result?.kind !== "payload_summary" || result.outcome !== "complete") return false;
  if (result.workload_outcome !== undefined && result.workload_outcome !== "complete") {
    return false;
  }
  if (result.failure != null) return false;
  if (result.close_outcome !== undefined && result.close_outcome !== "closed") return false;
  if (!Number.isSafeInteger(result.samples) || result.samples <= 0) return false;
  const counts = result.counts;
  if (!counts || typeof counts !== "object") return false;
  if (
    counts.attempted !== result.samples ||
    counts.sent !== result.samples ||
    counts.received !== result.samples ||
    result.not_attempted !== 0
  ) {
    return false;
  }
  return ["lost", "duplicate", "mismatch", "late", "busy_dropped", "send_outcome_unknown"].every(
    (name) => counts[name] === 0,
  );
}

export function classifyActionResult(action, result) {
  if (hasOutcomeUnknown(result)) return "outcome_unknown";
  if (action === "rpc") {
    if (result?.ok === true) return "acknowledged";
    if (result?.ok === false) return "failed";
    return "outcome_unknown";
  }
  if (action === "stop") return result?.requested === true ? "acknowledged" : "failed";
  if (PAYLOAD_ACTIONS.has(action)) {
    if (result?.kind === "echo_ready") return "ready";
    if (result?.kind === "relay_accepting") return "pending";
    return cleanPayloadResult(result) ? "passed" : "failed";
  }
  if (action === "role-stream") {
    return result?.status === "acknowledged_not_convergence" ? "acknowledged" : "failed";
  }
  if (action === "identity") return result?.identity ? "observed" : "failed";
  if (action === "converge") return result?.matched === true ? "passed" : "failed";
  if (action === "export") return result?.complete === true ? "passed" : "failed";
  return "failed";
}

function failureStatus(status) {
  return status === "failed" || status === "outcome_unknown" || status === "censored";
}

function statusError(status, message) {
  return failureStatus(status) ? new ControllerError(message, status) : null;
}

export function classifyLifetimeResult(action, result, cleanupError, doneError) {
  const errors = [cleanupError, doneError].filter(Boolean);
  if (errors.some((error) => commandErrorStatus(error) === "outcome_unknown")) {
    return "outcome_unknown";
  }
  const resultStatus = classifyActionResult(action, result);
  if (resultStatus === "outcome_unknown") return resultStatus;
  if (errors.length > 0) return "failed";
  return resultStatus;
}

export function mergeControllerError(current, next) {
  if (!next) return current;
  const candidate = next instanceof Error ? next : new ControllerError(String(next));
  if (!current) return candidate;
  const currentStatus = commandErrorStatus(current);
  const candidateStatus = commandErrorStatus(candidate);
  if (candidateStatus === "outcome_unknown" && currentStatus !== "outcome_unknown") {
    return candidate;
  }
  return current;
}

export function collectionDeadlineError(stopped, expired) {
  return !stopped && expired
    ? new ControllerError("collection duration expired before an explicit stop", "censored")
    : null;
}

export function controllerStatus(error) {
  if (!error) return "complete";
  if (error?.kind === "outcome_unknown") return "outcome_unknown";
  if (error?.kind === "censored") return "censored";
  return "failed";
}

async function sha256Bytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    const stream = createReadStream(filePath);
    stream.on("error", reject);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

function sameSnapshot(before, after) {
  return (
    before.dev === after.dev &&
    before.ino === after.ino &&
    before.size === after.size &&
    before.mtimeMs === after.mtimeMs &&
    before.ctimeMs === after.ctimeMs
  );
}

async function readBoundedFile(filePath, maxBytes, label) {
  const before = await stat(filePath);
  if (!before.isFile()) throw new ControllerError(`${label} is not a regular file`);
  if (before.size > maxBytes) throw new ControllerError(`${label} exceeds ${maxBytes} bytes`);
  const bytes = await readFile(filePath);
  const after = await stat(filePath);
  if (!sameSnapshot(before, after) || bytes.length !== after.size) {
    throw new ControllerError(`${label} changed while it was read`);
  }
  return bytes;
}

export async function readAtomicCommand(filePath, maxBytes = LIMITS.commandBytes) {
  let before;
  try {
    before = await stat(filePath);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
  if (!before.isFile()) throw new ControllerError("command input is not a regular file");
  if (before.size === 0) return null;
  if (before.size > maxBytes) throw new ControllerError(`command input exceeds ${maxBytes} bytes`);
  const bytes = await readFile(filePath);
  const after = await stat(filePath);
  const stable = sameSnapshot(before, after) && bytes.length === after.size;
  if (!stable) return null;
  let command;
  try {
    command = JSON.parse(bytes.toString("utf8"));
  } catch {
    return null;
  }
  if (command === null || Array.isArray(command) || typeof command !== "object") return null;
  if (typeof command.id !== "string" || command.id.length === 0) return null;
  if (
    Buffer.byteLength(command.id, "utf8") > LIMITS.commandIdBytes ||
    /[\u0000-\u001f]/.test(command.id)
  ) {
    return null;
  }
  if (
    typeof command.action !== "string" ||
    command.action.length === 0 ||
    Buffer.byteLength(command.action, "utf8") > 64 ||
    /[\u0000-\u001f]/.test(command.action)
  ) {
    return null;
  }
  return { command, digest: await sha256Bytes(bytes) };
}

export class JsonlWriter {
  constructor(handle, maxBytes = LIMITS.outputBytes) {
    this.handle = handle;
    this.maxBytes = maxBytes;
    this.bytes = 0;
    this.tail = Promise.resolve();
    this.failure = null;
  }

  static async create(filePath) {
    return new JsonlWriter(await open(filePath, "wx", 0o600));
  }

  append(record) {
    const task = this.tail.then(() => this.#append(record));
    this.tail = task.catch((error) => {
      this.failure ??= error;
    });
    return task;
  }

  async #append(record) {
    if (this.failure) throw this.failure;
    const safe = sanitizeEvidence(record);
    const encoded = Buffer.from(`${JSON.stringify(safe)}\n`, "utf8");
    if (encoded.length > LIMITS.outputRecordBytes) {
      throw new ControllerError("one output record exceeds the configured bound");
    }
    if (this.bytes + encoded.length > this.maxBytes) {
      throw new ControllerError("controller output exceeds the configured bound");
    }
    await this.handle.writeFile(encoded);
    await this.handle.sync();
    this.bytes += encoded.length;
  }

  async close() {
    await this.tail;
    let closeError;
    try {
      await this.handle.close();
    } catch (error) {
      closeError = error;
    }
    if (this.failure) throw this.failure;
    if (closeError) throw closeError;
  }
}

export function parseArgs(argv) {
  const values = new Map();
  let reuseHome = false;
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    if (key === "--reuse-home") {
      if (reuseHome) throw new ControllerError("duplicate --reuse-home");
      reuseHome = true;
      continue;
    }
    if (!key.startsWith("--") || index + 1 >= argv.length) {
      throw new ControllerError(`invalid argument ${key}`);
    }
    if (values.has(key)) throw new ControllerError(`duplicate argument ${key}`);
    values.set(key, argv[++index]);
  }
  const names = [
    "--binary",
    "--home",
    "--config",
    "--grant-file",
    "--commands",
    "--output",
    "--duration-ms",
  ];
  for (const name of names) {
    if (!values.has(name)) throw new ControllerError(`missing ${name}`);
  }
  for (const name of values.keys()) {
    if (!names.includes(name)) throw new ControllerError(`unknown argument ${name}`);
  }
  const result = {
    binary: values.get("--binary"),
    home: values.get("--home"),
    config: values.get("--config"),
    grantFile: values.get("--grant-file"),
    commands: values.get("--commands"),
    output: values.get("--output"),
    durationMs: Number(values.get("--duration-ms")),
    reuseHome,
  };
  for (const [name, value] of Object.entries(result)) {
    if (["durationMs", "reuseHome"].includes(name)) continue;
    if (!path.isAbsolute(value)) throw new ControllerError(`${name} must be absolute`);
  }
  if (
    !Number.isSafeInteger(result.durationMs) ||
    result.durationMs <= 0 ||
    result.durationMs > LIMITS.maxDurationMs
  ) {
    throw new ControllerError(
      `duration-ms must be an integer from 1 through ${LIMITS.maxDurationMs}`,
    );
  }
  return result;
}

async function prepareInputs(args) {
  await access(args.binary, process.platform === "win32" ? fsConstants.F_OK : fsConstants.X_OK);
  const binaryInfo = await stat(args.binary);
  if (!binaryInfo.isFile()) throw new ControllerError("binary is not a regular file");
  const binarySha256 = await sha256File(args.binary);
  const binaryAfterHash = await stat(args.binary);
  if (!sameSnapshot(binaryInfo, binaryAfterHash)) {
    throw new ControllerError("binary changed while it was hashed");
  }

  const configBytes = await readBoundedFile(args.config, LIMITS.configBytes, "config");
  let config;
  try {
    config = JSON.parse(configBytes.toString("utf8"));
  } catch (error) {
    throw new ControllerError("config is not valid JSON", "failed", error);
  }
  if (config === null || Array.isArray(config) || typeof config !== "object") {
    throw new ControllerError("config must be a JSON object");
  }
  if (config.auto_update?.enabled !== false || config.auto_update?.auto_apply !== "none") {
    throw new ControllerError(
      "trial config must explicitly set auto_update.enabled=false and auto_update.auto_apply=none",
    );
  }
  const configSha256 = await sha256Bytes(configBytes);

  const grantBytes = await readBoundedFile(args.grantFile, LIMITS.grantBytes, "grant file");
  const grant = grantBytes.toString("utf8").trim();
  if (grant.length === 0 || grant.includes("\0") || grant.includes("\r") || grant.includes("\n")) {
    throw new ControllerError("grant file must contain one nonempty line");
  }
  const grantSha256 = await sha256Bytes(grantBytes);

  const homeExists = existsSync(args.home);
  if (!args.reuseHome) {
    if (homeExists) throw new ControllerError("fresh home already exists; use a new path");
    await mkdir(args.home, { mode: 0o700, recursive: false });
    const installed = await open(path.join(args.home, "config.json"), "wx", 0o600);
    try {
      await installed.writeFile(configBytes);
      await installed.sync();
    } finally {
      await installed.close();
    }
  } else {
    if (!homeExists || !(await stat(args.home)).isDirectory()) {
      throw new ControllerError("--reuse-home requires an existing directory");
    }
    const installed = await readBoundedFile(
      path.join(args.home, "config.json"),
      LIMITS.configBytes,
      "installed config",
    );
    if ((await sha256Bytes(installed)) !== configSha256) {
      throw new ControllerError("reuse-home config does not match the supplied config");
    }
  }

  const actualHome = await realpath(args.home);
  const installedConfig = await realpath(path.join(args.home, "config.json"));
  if (path.dirname(installedConfig) !== actualHome) {
    throw new ControllerError("installed config escaped the isolated home");
  }
  return { binarySha256, configSha256, grantSha256, grant, config, actualHome };
}

export function controlEndpoint(home, config, platform = process.platform) {
  const configured = config?.daemon?.control_socket;
  if (platform === "win32") {
    if (configured === undefined || configured === null || configured === "") {
      return "\\\\.\\pipe\\myownmesh.sock";
    }
    const prefix = "\\\\.\\pipe\\myownmesh-live-";
    if (
      typeof configured !== "string" ||
      !configured.startsWith(prefix) ||
      !/^[A-Za-z0-9._-]{1,80}$/.test(configured.slice(prefix.length))
    ) {
      throw new ControllerError(
        "Windows control_socket must be an absolute local \\\\.\\pipe\\myownmesh-live-* name",
      );
    }
    return configured;
  }
  if (typeof configured === "string" && configured.length > 0) {
    return path.isAbsolute(configured) ? configured : path.resolve(home, configured);
  }
  return path.join(home, "daemon.sock");
}

function connectSocket(endpoint, timeoutMs, signal) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(endpoint);
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      socket.removeListener("error", onError);
      fn(value);
    };
    const onError = (error) => {
      socket.destroy();
      finish(reject, error);
    };
    const onAbort = () => {
      socket.destroy();
      const error = new ControllerError("controller deadline reached");
      error.code = "ABORT_ERR";
      finish(reject, error);
    };
    const timer = setTimeout(() => {
      socket.destroy();
      const error = new ControllerError("control endpoint connect timed out");
      error.code = "ETIMEDOUT";
      finish(reject, error);
    }, timeoutMs);
    socket.once("error", onError);
    socket.once("connect", () => finish(resolve, socket));
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) onAbort();
  });
}

export async function probeEndpoint(endpoint, timeoutMs) {
  try {
    const socket = await connectSocket(endpoint, timeoutMs);
    socket.destroy();
    return { reachable: true, error: null };
  } catch (error) {
    return { reachable: false, error };
  }
}

export function endpointProbeDisposition(platform, error) {
  if (platform === "win32") return error?.code === "ENOENT" ? "absent" : "refuse";
  return error?.code === "ENOENT" || error?.code === "ECONNREFUSED" ? "absent" : "refuse";
}

function endpointFailureMessage(prefix, error) {
  const code = typeof error?.code === "string" || typeof error?.code === "number"
    ? String(error.code)
    : "UNKNOWN";
  const message = typeof error?.message === "string" ? error.message : String(error);
  const wrapped = new ControllerError(`${prefix} (${code}): ${message}`, "failed", error);
  wrapped.code = code;
  return wrapped;
}

export class JsonLineConnection {
  constructor(socket, limits = LIMITS) {
    this.socket = socket;
    this.limits = limits;
    this.buffer = Buffer.alloc(0);
    this.frames = [];
    this.waiters = [];
    this.terminal = null;
    socket.on("data", (chunk) => this.#onData(chunk));
    socket.once("error", (error) => this.#finish(error));
    socket.once("close", () => this.#finish(new ControllerError("control connection closed")));
  }

  #finish(error) {
    if (this.terminal) return;
    this.terminal = error;
    while (this.waiters.length > 0) this.waiters.shift().reject(error);
  }

  #onData(chunk) {
    if (this.terminal) return;
    this.buffer = Buffer.concat([this.buffer, chunk]);
    if (this.buffer.length > this.limits.frameBytes && !this.buffer.includes(0x0a)) {
      this.socket.destroy(new ControllerError("unterminated IPC frame exceeded the bound"));
      return;
    }
    while (true) {
      const newline = this.buffer.indexOf(0x0a);
      if (newline < 0) break;
      const encoded = this.buffer.subarray(0, newline);
      this.buffer = this.buffer.subarray(newline + 1);
      if (encoded.length === 0 || encoded.length > this.limits.frameBytes) {
        this.socket.destroy(new ControllerError("IPC frame length is invalid"));
        return;
      }
      let frame;
      try {
        frame = JSON.parse(encoded.toString("utf8"));
      } catch (error) {
        this.socket.destroy(new ControllerError("IPC frame is not valid JSON", "failed", error));
        return;
      }
      if (this.waiters.length > 0) this.waiters.shift().resolve(frame);
      else if (this.frames.length < this.limits.queuedFrames) this.frames.push(frame);
      else {
        this.socket.destroy(new ControllerError("IPC frame queue exceeded the bound"));
        return;
      }
    }
  }

  nextFrame(timeoutMs, signal) {
    if (this.frames.length > 0) return Promise.resolve(this.frames.shift());
    if (this.terminal) return Promise.reject(this.terminal);
    let waiter;
    const pending = new Promise((resolve, reject) => {
      waiter = { resolve, reject };
      this.waiters.push(waiter);
    });
    return withTimeout(pending, timeoutMs, "IPC response timed out", signal).finally(() => {
      const index = this.waiters.indexOf(waiter);
      if (index >= 0) this.waiters.splice(index, 1);
    });
  }

  async send(request, timeoutMs, signal) {
    if (this.terminal) throw this.terminal;
    const encoded = Buffer.from(`${JSON.stringify(request)}\n`, "utf8");
    if (encoded.length > this.limits.frameBytes) {
      throw new ControllerError("IPC request exceeded the frame bound");
    }
    let attempted = false;
    try {
      attempted = true;
      await withTimeout(
        new Promise((resolve, reject) => {
          this.socket.write(encoded, (error) => (error ? reject(error) : resolve()));
        }),
        timeoutMs,
        "IPC write timed out",
        signal,
      );
    } catch (error) {
      throw new ControllerError(
        "IPC write outcome is unknown",
        attempted ? "outcome_unknown" : "failed",
        error,
      );
    }
  }

  close() {
    this.socket.destroy();
  }
}

class RpcClient {
  constructor(endpoint, deadlineMs, signal) {
    this.endpoint = endpoint;
    this.deadlineMs = deadlineMs;
    this.signal = signal;
    this.connection = null;
    this.tail = Promise.resolve();
    this.pending = 0;
  }

  async #ensure(timeoutMs) {
    if (this.connection && !this.connection.terminal) return this.connection;
    const socket = await connectSocket(this.endpoint, timeoutMs, this.signal);
    this.connection = new JsonLineConnection(socket);
    return this.connection;
  }

  rpc(request, requestedMs) {
    if (request === null || Array.isArray(request) || typeof request !== "object") {
      return Promise.reject(new ControllerError("rpc request must be an object"));
    }
    if (this.pending >= LIMITS.queuedFrames) {
      return Promise.reject(new ControllerError("RPC request queue exceeded the bound"));
    }
    this.pending += 1;
    const task = this.tail.then(
      () => this.#rpcOne(request, requestedMs),
      () => this.#rpcOne(request, requestedMs),
    );
    this.tail = task.catch(() => {});
    return task.finally(() => {
      this.pending -= 1;
    });
  }

  async #rpcOne(request, requestedMs) {
    const timeoutMs = remainingMs(this.deadlineMs, requestedMs);
    let sent = false;
    try {
      const connection = await this.#ensure(timeoutMs);
      await connection.send(request, timeoutMs, this.signal);
      sent = true;
      return await connection.nextFrame(timeoutMs, this.signal);
    } catch (error) {
      this.connection?.close();
      this.connection = null;
      if (error?.kind === "outcome_unknown" || sent) {
        throw new ControllerError("RPC outcome is unknown", "outcome_unknown", error);
      }
      throw new ControllerError("RPC failed before a request was sent", "failed", error);
    }
  }

  close() {
    this.connection?.close();
    this.connection = null;
  }
}

class EventHub {
  constructor(endpoint, rpc, deadlineMs, signal) {
    this.endpoint = endpoint;
    this.rpc = rpc;
    this.deadlineMs = deadlineMs;
    this.signal = signal;
    this.connection = null;
    this.clientId = null;
    this.clientCapability = null;
    this.subscriptions = new Map();
    this.events = 0;
    this.worker = null;
    this.failure = null;
  }

  async #ensure() {
    if (this.connection && !this.connection.terminal) return;
    const timeoutMs = remainingMs(this.deadlineMs, LIMITS.rpcMs);
    const socket = await connectSocket(this.endpoint, timeoutMs, this.signal);
    const connection = new JsonLineConnection(socket);
    let sent = false;
    try {
      await connection.send({ op: "events_subscribe" }, timeoutMs, this.signal);
      sent = true;
      const reply = await connection.nextFrame(timeoutMs, this.signal);
      const data = reply?.data;
      if (
        reply?.ok !== true ||
        typeof data?.client_id !== "string" ||
        typeof data?.client_capability !== "string"
      ) {
        throw new ControllerError("events_subscribe was refused");
      }
      this.connection = connection;
      this.clientId = data.client_id;
      this.clientCapability = data.client_capability;
      this.worker = this.#run();
    } catch (error) {
      connection.close();
      if (sent) throw new ControllerError("events_subscribe outcome is unknown", "outcome_unknown", error);
      throw error;
    }
  }

  async #run() {
    try {
      while (!this.signal.aborted && this.connection && !this.connection.terminal) {
        const waitMs = remainingMs(this.deadlineMs, 1000);
        let frame;
        try {
          frame = await this.connection.nextFrame(waitMs, this.signal);
        } catch (error) {
          if (this.signal.aborted || error?.message === "IPC response timed out") continue;
          throw error;
        }
        this.events += 1;
        if (this.events > LIMITS.events) throw new ControllerError("event count exceeded the bound");
        if (frame?.kind !== "channel_inbound") continue;
        for (const subscription of this.subscriptions.values()) {
          if (frame.network === subscription.network && frame.channel === subscription.channel) {
            await subscription.onEvent(frame);
          }
        }
      }
    } catch (error) {
      if (!this.signal.aborted) this.failure = error;
      this.connection?.close();
    }
  }

  async subscribe(network, channel, onEvent) {
    if (typeof network !== "string" || typeof channel !== "string" || typeof onEvent !== "function") {
      throw new ControllerError("subscribe requires network, channel, and callback");
    }
    if (this.subscriptions.size >= LIMITS.subscriptions) {
      throw new ControllerError("subscription count exceeded the bound");
    }
    if (this.failure) throw this.failure;
    await this.#ensure();
    const key = `${network}\u0000${channel}`;
    if (this.subscriptions.has(key)) throw new ControllerError("duplicate channel subscription");
    const reply = await this.rpc.rpc(
      {
        op: "channel_subscribe",
        client_id: this.clientId,
        client_capability: this.clientCapability,
        network,
        channel,
      },
      LIMITS.rpcMs,
    );
    requireOk(reply);
    this.subscriptions.set(key, { network, channel, onEvent });
    let cleaned = false;
    return async () => {
      if (cleaned) return;
      cleaned = true;
      const owned = this.subscriptions.delete(key);
      if (!owned) return;
      const response = await this.rpc.rpc(
        {
          op: "channel_unsubscribe",
          client_id: this.clientId,
          client_capability: this.clientCapability,
          network,
          channel,
        },
        LIMITS.rpcMs,
      );
      requireOk(response);
    };
  }

  async close() {
    this.subscriptions.clear();
    this.connection?.close();
    if (this.worker) await Promise.resolve(this.worker).catch(() => {});
    if (this.failure) throw this.failure;
  }
}

export function requireOk(reply) {
  if (reply?.ok !== true) {
    const error = typeof reply?.error === "string" ? reply.error : "daemon refused request";
    throw new ControllerError(error);
  }
  return reply.data;
}

async function waitForDaemon(endpoint, child, deadlineMs, signal) {
  const readyDeadline = Math.min(deadlineMs, monoMs() + LIMITS.readyMs);
  let lastError;
  while (monoMs() < readyDeadline) {
    if (child.exitCode !== null || child.signalCode !== null) {
      throw endpointFailureMessage(
        "daemon exited before its control endpoint became reachable; last endpoint error",
        lastError ?? new ControllerError("endpoint was not probed", "failed"),
      );
    }
    const probe = await probeEndpoint(
      endpoint,
      Math.min(250, Math.max(1, readyDeadline - monoMs())),
    );
    if (probe.reachable) {
      return;
    }
    lastError = probe.error;
    await sleep(Math.min(LIMITS.pollMs, Math.max(1, readyDeadline - monoMs())), signal);
  }
  throw endpointFailureMessage(
    "daemon control endpoint did not become reachable; last endpoint error",
    lastError ?? new ControllerError("endpoint was not probed", "failed"),
  );
}

function spawnDaemon(args, prepared) {
  const stdoutPath = `${args.output}.daemon.stdout.log`;
  const stderrPath = `${args.output}.daemon.stderr.log`;
  const stdoutFd = openSync(stdoutPath, "wx", 0o600);
  let stderrFd;
  try {
    stderrFd = openSync(stderrPath, "wx", 0o600);
    const child = spawn(args.binary, ["serve"], {
      cwd: prepared.actualHome,
      env: {
        ...process.env,
        MYOWNMESH_HOME: prepared.actualHome,
        MYOWNMESH_RESOURCE_GRANT: prepared.grant,
        MYOWNMESH_CONNECTOR_REALTIME_POLICY: "disabled",
        MYOWNMESH_AUTOUPDATE: "0",
        MYOWNMESH_LOG_FORMAT: "json",
        MYOWNMESH_CONN_TRACE: "1",
      },
      detached: process.platform !== "win32",
      windowsHide: true,
      stdio: ["ignore", stdoutFd, stderrFd],
    });
    const started = new Promise((resolve, reject) => {
      child.once("spawn", resolve);
      child.once("error", reject);
    });
    return { child, started, stdoutPath, stderrPath };
  } finally {
    closeSync(stdoutFd);
    if (stderrFd !== undefined) closeSync(stderrFd);
  }
}

function waitForChildExit(child, timeoutMs) {
  if (child.exitCode !== null || child.signalCode !== null) {
    return Promise.resolve({ exitCode: child.exitCode, signal: child.signalCode });
  }
  return withTimeout(
    new Promise((resolve) =>
      child.once("exit", (exitCode, signal) => resolve({ exitCode, signal })),
    ),
    timeoutMs,
    "daemon did not exit before the shutdown deadline",
  );
}

async function stopOwnedChild(child, deadlineMs) {
  if (child.exitCode !== null || child.signalCode !== null) {
    return {
      mode: "already_exited",
      graceful: false,
      durability_claim: false,
      exitCode: child.exitCode,
      signal: child.signalCode,
    };
  }
  if (!Number.isInteger(child.pid) || child.pid <= 0) {
    return {
      mode: "spawn_failed",
      graceful: false,
      durability_claim: false,
      exitCode: child.exitCode,
      signal: child.signalCode,
    };
  }
  const bounded = Math.max(1, Math.min(LIMITS.shutdownMs, deadlineMs - monoMs()));
  if (process.platform === "win32") {
    const sent = child.kill();
    const terminal = await waitForChildExit(child, bounded);
    return {
      mode: "forced_owned_child",
      graceful: false,
      durability_claim: false,
      signalSent: sent,
      ...terminal,
    };
  }
  let gracefulSent = false;
  try {
    process.kill(-child.pid, "SIGINT");
    gracefulSent = true;
  } catch (error) {
    if (error?.code !== "ESRCH") throw error;
  }
  try {
    return {
      mode: "graceful_sigint",
      graceful: true,
      durability_claim: false,
      signalSent: gracefulSent,
      ...(await waitForChildExit(child, bounded)),
    };
  } catch {
    let forcedSent = false;
    try {
      process.kill(-child.pid, "SIGKILL");
      forcedSent = true;
    } catch (error) {
      if (error?.code !== "ESRCH") throw error;
    }
    const terminal = await waitForChildExit(child, Math.max(1, deadlineMs - monoMs()));
    return {
      mode: "forced_sigkill",
      graceful: false,
      durability_claim: false,
      signalSent: forcedSent,
      ...terminal,
    };
  }
}

async function loadRunner(action) {
  const specifier = FACT_ACTIONS.has(action)
    ? path.join(HERE, "live-device-facts.mjs")
    : path.join(HERE, "live-device-payload.mjs");
  const module = await import(pathToFileURL(specifier).href);
  const runner = FACT_ACTIONS.has(action) ? module.runFacts : module.runPayload;
  if (typeof runner !== "function") throw new ControllerError(`module for ${action} has no runner export`);
  return runner;
}

function isLifetimeEnvelope(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    typeof value.cleanup === "function" &&
    value.done &&
    typeof value.done.then === "function" &&
    Object.hasOwn(value, "result")
  );
}

async function executeCommand(command, baseContext, lifetimes) {
  if (command.action === "stop") return { stop: true, result: { requested: true } };
  if (command.action === "rpc") {
    if (command.request === null || Array.isArray(command.request) || typeof command.request !== "object") {
      throw new ControllerError("rpc action requires a request object");
    }
    if (typeof command.request.op !== "string" || STREAM_MODE_OPS.has(command.request.op)) {
      throw new ControllerError("rpc action requires a finite request/response operation");
    }
    return { stop: false, result: await baseContext.rpc(command.request, command.timeoutMs) };
  }
  if (!FACT_ACTIONS.has(command.action) && !PAYLOAD_ACTIONS.has(command.action)) {
    throw new ControllerError(`unsupported action ${command.action}`);
  }
  if (command.action === "export") {
    if (
      !Number.isSafeInteger(command.maxPages) ||
      command.maxPages <= 0 ||
      !Number.isSafeInteger(command.maxEncodedBytes) ||
      command.maxEncodedBytes <= 0
    ) {
      throw new ControllerError("export requires positive maxPages and maxEncodedBytes");
    }
    const aggregate = command.maxPages * command.maxEncodedBytes;
    if (
      !Number.isSafeInteger(aggregate) ||
      aggregate + 1024 * 1024 > LIMITS.outputRecordBytes ||
      aggregate * 2 + 4 * 1024 * 1024 > LIMITS.outputBytes
    ) {
      throw new ControllerError("export evidence bounds exceed controller output capacity");
    }
  }
  const runner = await loadRunner(command.action);
  const value = await runner(baseContext, command);
  if (!isLifetimeEnvelope(value)) return { stop: false, result: value };
  lifetimes.push({
    commandId: command.id,
    action: command.action,
    cleanup: value.cleanup,
    done: value.done,
    cleaned: false,
  });
  return { stop: false, result: value.result };
}

async function drainLifetimes(lifetimes, deadlineMs, writer) {
  let aggregateError;
  for (const lifetime of lifetimes.reverse()) {
    const startedMs = monoMs();
    let cleanupError;
    if (!lifetime.cleaned) {
      lifetime.cleaned = true;
      try {
        await withTimeout(
          Promise.resolve(lifetime.cleanup()),
          remainingMs(deadlineMs, LIMITS.shutdownMs),
          "module cleanup timed out",
        );
      } catch (error) {
        cleanupError = errorEvidence(error);
      }
    }
    let done;
    let doneError;
    try {
      done = await withTimeout(
        Promise.resolve(lifetime.done),
        remainingMs(deadlineMs, LIMITS.shutdownMs),
        "module terminal observation timed out",
      );
    } catch (error) {
      doneError = errorEvidence(error);
    }
    const status = classifyLifetimeResult(lifetime.action, done, cleanupError, doneError);
    aggregateError = mergeControllerError(
      aggregateError,
      statusError(status, `module lifetime ${lifetime.commandId} ended ${status}`),
    );
    await writer.append({
      type: "lifetime_terminal",
      id: lifetime.commandId,
      action: lifetime.action,
      mono_ms: monoMs(),
      elapsed_ms: monoMs() - startedMs,
      status,
      result: done,
      cleanup_error: cleanupError,
      done_error: doneError,
    });
  }
  if (aggregateError) throw aggregateError;
}

export async function runController(args) {
  const startedMs = monoMs();
  const deadlineMs = startedMs + args.durationMs;
  const writer = await JsonlWriter.create(args.output);
  const workAbort = new AbortController();
  const transportAbort = new AbortController();
  let externalSignal = null;
  const onSigint = () => {
    externalSignal = "SIGINT";
    workAbort.abort();
  };
  const onSigterm = () => {
    externalSignal = "SIGTERM";
    workAbort.abort();
  };
  process.on("SIGINT", onSigint);
  process.on("SIGTERM", onSigterm);
  const timer = setTimeout(() => workAbort.abort(), args.durationMs);
  timer.unref?.();
  let child;
  let rpc;
  let events;
  const lifetimes = [];
  let controllerError;
  try {
    const prepared = await prepareInputs(args);
    const endpoint = controlEndpoint(prepared.actualHome, prepared.config);
    const preflightProbe = await probeEndpoint(endpoint, 500);
    if (preflightProbe.reachable) {
      throw new ControllerError("a daemon is already reachable at the production control endpoint");
    }
    if (endpointProbeDisposition(process.platform, preflightProbe.error) !== "absent") {
      throw endpointFailureMessage(
        "control endpoint preflight could not prove the endpoint absent",
        preflightProbe.error,
      );
    }
    const launched = spawnDaemon(args, prepared);
    child = launched.child;
    await withTimeout(
      launched.started,
      remainingMs(deadlineMs, LIMITS.readyMs),
      "daemon process did not start",
      workAbort.signal,
    );
    const spawnedWallTime = new Date().toISOString();
    await writer.append({
      type: "controller_start",
      mono_ms: monoMs(),
      wall_time: spawnedWallTime,
      hostname: os.hostname(),
      platform: process.platform,
      arch: process.arch,
      node: process.version,
      binary: args.binary,
      binary_sha256: prepared.binarySha256,
      config_sha256: prepared.configSha256,
      grant_sha256: prepared.grantSha256,
      home: prepared.actualHome,
      reuse_home: args.reuseHome,
      endpoint,
      pid: child.pid,
      daemon_stdout: launched.stdoutPath,
      daemon_stderr: launched.stderrPath,
      deadline_ms: deadlineMs,
    });
    if ((await sha256File(args.binary)) !== prepared.binarySha256) {
      throw new ControllerError("binary changed between preflight and process start");
    }
    await writer.append({
      type: "binary_reverified",
      mono_ms: monoMs(),
      binary_sha256: prepared.binarySha256,
      pid: child.pid,
    });
    await waitForDaemon(endpoint, child, deadlineMs, workAbort.signal);
    await writer.append({ type: "daemon_ready", mono_ms: monoMs(), pid: child.pid });
    rpc = new RpcClient(endpoint, deadlineMs, transportAbort.signal);
    events = new EventHub(endpoint, rpc, deadlineMs, workAbort.signal);
    const seen = new Set();
    let commands = 0;
    let commandFailures = 0;
    let unknownOutcome;
    let lastRejectedDigest = null;
    let stop = false;
    while (
      !stop &&
      !workAbort.signal.aborted &&
      monoMs() < deadlineMs &&
      child.exitCode === null &&
      child.signalCode === null
    ) {
      let input;
      try {
        input = await readAtomicCommand(args.commands);
      } catch (error) {
        const digest = `error:${error?.message}`;
        if (digest !== lastRejectedDigest) {
          lastRejectedDigest = digest;
          await writer.append({ type: "command_input_refused", mono_ms: monoMs(), error: errorEvidence(error) });
        }
        try {
          await sleep(
            Math.min(LIMITS.pollMs, remainingMs(deadlineMs, LIMITS.pollMs)),
            workAbort.signal,
          );
        } catch (error) {
          if (!workAbort.signal.aborted && monoMs() < deadlineMs) throw error;
        }
        continue;
      }
      if (!input || seen.has(input.command.id)) {
        try {
          await sleep(
            Math.min(LIMITS.pollMs, remainingMs(deadlineMs, LIMITS.pollMs)),
            workAbort.signal,
          );
        } catch (error) {
          if (!workAbort.signal.aborted && monoMs() < deadlineMs) throw error;
        }
        continue;
      }
      lastRejectedDigest = null;
      commands += 1;
      if (commands > LIMITS.commands) throw new ControllerError("command count exceeded the bound");
      const command = input.command;
      seen.add(command.id);
      const commandStartedMs = monoMs();
      await writer.append({
        type: "command_started",
        id: command.id,
        action: command.action,
        command_sha256: input.digest,
        mono_ms: commandStartedMs,
      });
      const context = Object.freeze({
        rpc: (request, timeoutMs) => rpc.rpc(request, timeoutMs),
        requireOk,
        subscribe: (network, channel, onEvent) => events.subscribe(network, channel, onEvent),
        monoMs,
        get deadlineMs() {
          return rpc.deadlineMs;
        },
        emit: (record) =>
          writer.append({ type: "module_event", id: command.id, mono_ms: monoMs(), record }),
        signal: workAbort.signal,
      });
      try {
        const outcome = await executeCommand(command, context, lifetimes);
        const status = classifyActionResult(command.action, outcome.result);
        try {
          await writer.append({
            type: "command_result",
            id: command.id,
            action: command.action,
            status,
            mono_ms: monoMs(),
            elapsed_ms: monoMs() - commandStartedMs,
            result: outcome.result,
          });
        } catch (captureError) {
          throw new ControllerError(
            "command result capture failed",
            status === "outcome_unknown" ? "outcome_unknown" : "failed",
            captureError,
          );
        }
        if (failureStatus(status)) commandFailures += 1;
        if (status === "outcome_unknown") {
          unknownOutcome = new ControllerError(
            `command ${command.id} returned an unknown outcome`,
            "outcome_unknown",
          );
          break;
        }
        stop = outcome.stop;
      } catch (error) {
        const status = commandErrorStatus(error);
        commandFailures += 1;
        try {
          await writer.append({
            type: "command_result",
            id: command.id,
            action: command.action,
            status,
            mono_ms: monoMs(),
            elapsed_ms: monoMs() - commandStartedMs,
            error: errorEvidence(error),
          });
        } catch (captureError) {
          throw new ControllerError(
            "command terminal capture failed",
            status === "outcome_unknown" ? "outcome_unknown" : "failed",
            captureError,
          );
        }
        if (status === "outcome_unknown") {
          unknownOutcome = error;
          break;
        }
      }
    }
    if (unknownOutcome) throw unknownOutcome;
    if (
      !stop &&
      !workAbort.signal.aborted &&
      (child.exitCode !== null || child.signalCode !== null)
    ) {
      throw new ControllerError("daemon exited before controller completion");
    }
    if (externalSignal) throw new ControllerError(`controller interrupted by ${externalSignal}`);
    const deadlineError = collectionDeadlineError(
      stop,
      workAbort.signal.aborted || monoMs() >= deadlineMs,
    );
    if (deadlineError) throw deadlineError;
    if (commandFailures > 0) {
      throw new ControllerError(`${commandFailures} command(s) failed`);
    }
  } catch (error) {
    controllerError = mergeControllerError(controllerError, error);
    try {
      await writer.append({
        type: "controller_failure",
        mono_ms: monoMs(),
        status: controllerStatus(error),
        error: errorEvidence(error),
      });
    } catch (captureError) {
      controllerError = mergeControllerError(controllerError, captureError);
    }
  } finally {
    const cleanupDeadlineMs = monoMs() + LIMITS.shutdownMs;
    if (rpc) rpc.deadlineMs = cleanupDeadlineMs;
    workAbort.abort();
    await drainLifetimes(lifetimes, cleanupDeadlineMs, writer).catch((error) => {
      controllerError = mergeControllerError(controllerError, error);
    });
    try {
      if (events) {
        await withTimeout(
          events.close(),
          Math.max(1, cleanupDeadlineMs - monoMs()),
          "controller event stream cleanup timed out",
        );
      }
    } catch (error) {
      controllerError = mergeControllerError(controllerError, error);
      try {
        await writer.append({
          type: "controller_stream_failure",
          mono_ms: monoMs(),
          error: errorEvidence(error),
        });
      } catch (captureError) {
        controllerError = mergeControllerError(controllerError, captureError);
      }
    }
    rpc?.close();
    transportAbort.abort();
    let childTerminal;
    if (child) {
      try {
        childTerminal = await stopOwnedChild(child, monoMs() + LIMITS.shutdownMs);
      } catch (error) {
        childTerminal = { mode: "cleanup_failed", error: errorEvidence(error) };
        controllerError = mergeControllerError(controllerError, error);
      }
    }
    try {
      await writer.append({
        type: "controller_terminal",
        mono_ms: monoMs(),
        elapsed_ms: monoMs() - startedMs,
        status: controllerStatus(controllerError),
        output_close_pending: true,
        external_signal: externalSignal,
        child: childTerminal,
      });
    } catch (captureError) {
      controllerError = mergeControllerError(controllerError, captureError);
    }
    clearTimeout(timer);
    process.removeListener("SIGINT", onSigint);
    process.removeListener("SIGTERM", onSigterm);
    try {
      await writer.close();
    } catch (closeError) {
      controllerError = mergeControllerError(controllerError, closeError);
    }
  }
  if (controllerError) throw controllerError;
}

export async function main(argv = process.argv.slice(2)) {
  return runController(parseArgs(argv));
}

const invoked = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (invoked) {
  main().catch(() => {
    process.stderr.write("live-device-peer failed; inspect the bounded output and daemon logs\n");
    process.exitCode = 1;
  });
}
