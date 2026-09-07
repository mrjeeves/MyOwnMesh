import assert from "node:assert/strict";
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { EventEmitter } from "node:events";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";

import {
  ControllerError,
} from "../live-device-peer.mjs";
import {
  AtomicJsonPublisher,
  GRANT_DIMENSIONS,
  ResourceSampler,
  boundedHostErrorEvidence,
  enforceHostGrantLedger,
  hostProcessFailureRecord,
  parseGrant,
  parseJournal,
  runScaleHost,
  samplerFreshnessMs,
  samplerObservationError,
  settleDiagnosticCapture,
  validateManifest,
} from "../run-live-device-scale-host.mjs";

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

function atomicFailure(code = "EPERM", syscall = "rename") {
  return Object.assign(new Error("private path omitted"), { code, syscall, errno: -4048 });
}

function atomicFs(renameActions = []) {
  const files = new Map(), renames = [];
  let nextId = 1n, clock = 1n;
  const key = (value) => path.win32.resolve(value).toLowerCase();
  const touch = (entry) => {
    entry.mtimeNs = ++clock;
    entry.ctimeNs = clock;
  };
  const snapshot = (entry) => ({
    dev: 1n, ino: entry.id, size: BigInt(entry.bytes.length),
    mtimeNs: entry.mtimeNs, ctimeNs: entry.ctimeNs, isFile: () => true,
  });
  const missing = () => Object.assign(new Error("missing"), { code: "ENOENT" });
  const api = {
    files,
    renames,
    unreadable: new Set(),
    async open(file, flag) {
      const name = key(file);
      if (flag === "r") {
        const entry = files.get(name);
        if (!entry) throw missing();
        if (api.unreadable.has(name)) throw Object.assign(new Error("denied"), { code: "EACCES" });
        return {
          async stat() { return snapshot(entry); },
          async read(buffer, offset, length, position) {
            const available = Math.max(0, entry.bytes.length - position);
            const count = Math.min(length, available);
            entry.bytes.copy(buffer, offset, position, position + count);
            return { bytesRead: count, buffer };
          },
          async close() {},
        };
      }
      assert.equal(flag, "wx");
      if (files.has(name)) throw Object.assign(new Error("exists"), { code: "EEXIST" });
      const entry = { id: nextId++, bytes: Buffer.alloc(0), mtimeNs: ++clock, ctimeNs: clock };
      files.set(name, entry);
      return {
        async stat() { return snapshot(entry); },
        async writeFile(bytes) { entry.bytes = Buffer.from(bytes); touch(entry); },
        async sync() {},
        async close() {},
      };
    },
    async stat(file) {
      const entry = files.get(key(file));
      if (!entry) throw missing();
      return snapshot(entry);
    },
    async rename(source, destination) {
      const sourceKey = key(source), destinationKey = key(destination);
      const action = renameActions[renames.length];
      renames.push({ source: sourceKey, destination: destinationKey });
      if (typeof action === "function") return action({ api, sourceKey, destinationKey });
      if (action instanceof Error) throw action;
      const entry = files.get(sourceKey);
      if (!entry) throw missing();
      files.set(destinationKey, entry);
      files.delete(sourceKey);
    },
    async unlink(file) {
      if (!files.delete(key(file))) throw missing();
    },
    setJson(file, value) {
      const name = key(file), entry = files.get(name) ?? {
        id: nextId++, bytes: Buffer.alloc(0), mtimeNs: ++clock, ctimeNs: clock,
      };
      entry.bytes = Buffer.from(`${JSON.stringify(value)}\n`);
      touch(entry);
      files.set(name, entry);
    },
    json(file) { return JSON.parse(files.get(key(file)).bytes.toString("utf8")); },
    touch(file) {
      const entry = files.get(key(file));
      if (!entry) throw missing();
      touch(entry);
    },
    remove(file) { files.delete(key(file)); },
    key,
  };
  return api;
}

function atomicPublisher(fs, overrides = {}) {
  let now = 0;
  const abort = overrides.abort ?? new AbortController();
  const publisher = new AtomicJsonPublisher("C:\\evidence\\resource-manifest.json", "atomic-control", {
    platform: overrides.platform ?? "win32",
    open: overrides.open ?? fs.open, rename: fs.rename, stat: fs.stat, unlink: fs.unlink,
    randomUUID: (() => { let value = 0; return () => `test-${++value}`; })(),
    monoMs: () => now,
    wait: overrides.wait ?? (async (ms) => { now += ms; }),
    signal: abort.signal,
    isClosed: overrides.isClosed ?? (() => false),
    absoluteDeadlineMs: overrides.absoluteDeadlineMs ?? 10_000,
    heartbeatMs: overrides.heartbeatMs ?? 100,
    maxManifestAgeMs: overrides.maxManifestAgeMs ?? 1_000,
    maxBytes: 64 * 1024,
  });
  return { publisher, abort, now: () => now, setNow: (value) => { now = value; } };
}

function atomicManifest(revision, phase = "startup") {
  return { schema: "myownmesh-owned-resources/v1", runId: "atomic-control",
    revision, phase, owners: [], files: [] };
}

async function heartbeatCloseControl(
  heartbeatFailure = null,
  signal = new AbortController().signal,
  holdRevision = 4,
) {
  const root = await mkdtemp(path.join(os.tmpdir(), "myownmesh-sampler-close-"));
  const policyPath = path.join(root, "policy.json");
  await writeFile(policyPath, JSON.stringify({
    schema: "myownmesh-resource-policy/v1",
    runId: "heartbeat-close-control",
    sampleIntervalMs: 1_000,
    maxSweepMs: 1_000,
    maxManifestAgeMs: 5_000,
    maxInputBytes: 64 * 1024,
  }));
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.pid = 4242;
  child.exitCode = null;
  child.signalCode = null;
  const releaseHeartbeat = deferred(), heartbeatStarted = deferred();
  const writes = [];
  let tick, violations = 0;
  const sampler = new ResourceSampler({
    files: [],
    policyPath,
    manifestPath: path.join(root, "resource-manifest.json"),
    scriptPath: path.join(root, "live-device-resources.ps1"),
    heartbeatMs: 500,
  }, "heartbeat-close-control", signal, {
    spawn: () => {
      queueMicrotask(() => {
        child.emit("spawn");
        child.stdout.write(`${JSON.stringify({
          kind: "sample", decision: "Freeze", complete: false,
          reasons: ["owner_unconfirmed"], lastAcceptedRevision: 1,
          processes: [{ ownerId: "host-controller", registrationState: "unconfirmed",
            creationTimeUtcTicks: "638612345678901234" }],
        })}\n`);
      });
      return child;
    },
    atomicWrite: async (_file, manifest) => {
      writes.push(manifest);
      if (manifest.revision === 2) {
        queueMicrotask(() => child.stdout.write(`${JSON.stringify({
          kind: "sample", decision: "Continue", complete: true, reasons: [],
          lastAcceptedRevision: 2,
          processes: [{ ownerId: "host-controller", registrationState: "confirmed",
            creationTimeUtcTicks: "638612345678901234" }],
        })}\n`));
      }
      if (manifest.revision === holdRevision) {
        heartbeatStarted.resolve();
        await releaseHeartbeat.promise;
        if (heartbeatFailure) throw heartbeatFailure;
      }
    },
    setInterval: (callback) => {
      tick = callback;
      return { unref() {} };
    },
    clearInterval: () => {},
    onViolation: () => { violations += 1; },
  });
  await sampler.start();
  return {
    sampler, child, writes, heartbeatStarted, releaseHeartbeat,
    tick: () => tick(),
    violations: () => violations,
  };
}

const grantText = (value = 1) => GRANT_DIMENSIONS.map((name) => `${name}=${value}`).join(",");

function encode32(bytes) {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let bits = 0;
  let accumulator = 0;
  let result = "";
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result += alphabet[(accumulator >> bits) & 31];
    }
    accumulator &= (1 << bits) - 1;
  }
  if (bits) result += alphabet[(accumulator << (5 - bits)) & 31];
  return result;
}

const publicIds = Array.from({ length: 10 }, (_, index) => {
  const seed = createHash("sha256").update(`scale-host-test-only:${index}`).digest();
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
    format: "der",
    type: "pkcs8",
  });
  return encode32(createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32));
});

test("the host resource ledger is componentwise and refuses N+1", () => {
  const grant = parseGrant(grantText(2));
  const ledger = Object.fromEntries(GRANT_DIMENSIONS.map((name) => [name, "4"]));
  const evidence = enforceHostGrantLedger([grant, grant], ledger);
  assert.deepEqual(evidence.accounted_memory_bytes, { admitted: "4", limit: "4" });
  assert.throws(
    () => enforceHostGrantLedger([grant, grant, grant], ledger),
    /aggregate grant exceeds host ledger/,
  );
});

test("journal accepts only complete append-only newline-delimited history", () => {
  const first = Buffer.from('{"sequence":1,"kind":"phase","phase":"warm","commands":[{}]}\n');
  const parsed = parseJournal(first);
  assert.equal(parsed.rows.length, 1);
  assert.equal(parseJournal(Buffer.from("{}")), null);
  assert.throws(() => parseJournal(Buffer.alloc(0), parsed.digests), /truncated accepted history/);
  assert.throws(
    () => parseJournal(Buffer.from('{"sequence":1,"kind":"complete"}\n'), parsed.digests),
    /rewrote accepted history/,
  );
});

test("sampler health permits only bootstrap confirmation and derives freshness from policy", () => {
  assert.equal(samplerFreshnessMs({ sampleIntervalMs: 750, maxSweepMs: 1250 }), 2000);
  assert.equal(samplerObservationError({ kind: "sample", decision: "Freeze",
    complete: false, reasons: ["owner_unconfirmed"] }, "startup"), null);
  assert.equal(samplerObservationError({ kind: "sample", decision: "Continue",
    complete: true, reasons: [] }, "steady"), null);
  assert.ok(samplerObservationError({ kind: "sample", decision: "Freeze",
    complete: false, reasons: ["owner_unconfirmed"] }, "steady"));
  assert.match(samplerObservationError({ kind: "sample", decision: "StopTrial",
    complete: false, reasons: ["private_limit"] }, "steady").message, /StopTrial/);
  assert.equal(samplerObservationError({ kind: "terminal", success: true,
    observedRequiredExited: true }, "complete"), null);
  assert.ok(samplerObservationError({ kind: "terminal", success: false }, "steady"));
});

test("host errors retain only allowlisted OS and lifecycle discrimination", () => {
  const cause = Object.assign(new Error("SECRET path C:/private/config.json"), {
    name: "SECRET_NAME",
    code: "EPERM",
    syscall: "rename",
    errno: -4048,
    path: "C:/private/config.json",
    dest: "C:/private/manifest.json",
    token: "SECRET_TOKEN",
  });
  const error = new ControllerError("SECRET outer message", "outcome_unknown", cause);
  const evidence = boundedHostErrorEvidence(error, "sampler_manifest_heartbeat");
  assert.deepEqual(evidence, {
    name: "ControllerError",
    kind: "outcome_unknown",
    lifecycle_stage: "sampler_manifest_heartbeat",
    os_code: "EPERM",
    syscall: "rename",
    errno: -4048,
  });
  const terminal = JSON.stringify(hostProcessFailureRecord(error));
  assert.doesNotMatch(terminal, /SECRET|private|config\.json|TOKEN|stack|path|dest/);
  assert.doesNotMatch(
    JSON.stringify(boundedHostErrorEvidence(Object.assign(new Error("hidden"), {
      code: "SECRET_CODE", syscall: "SECRET_SYSCALL", errno: 9_999_999,
    }), "SECRET_STAGE")),
    /SECRET/,
  );
});

test("diagnostic capture refuses to extend an exhausted host deadline", async () => {
  assert.deepEqual(
    await settleDiagnosticCapture(new Promise(() => {}), 10, () => 10),
    { status: "censored" },
  );
  assert.deepEqual(
    await settleDiagnosticCapture(Promise.resolve({ status: "complete" }), 10, () => 0),
    { status: "complete" },
  );
});

test("Windows manifest replacement retries the same synced temp and commits one revision", async () => {
  const fs = atomicFs([undefined, atomicFailure(), undefined]);
  const { publisher } = atomicPublisher(fs);
  await publisher.publish(atomicManifest(1));
  await publisher.publish(atomicManifest(2));
  assert.equal(fs.renames.length, 3);
  assert.equal(fs.renames[1].source, fs.renames[2].source);
  assert.equal(fs.json("C:\\evidence\\resource-manifest.json").revision, 2);
  assert.equal([...fs.files.keys()].some((name) => name.endsWith(".tmp")), false);
});

test("a Windows retry re-proves temp, target snapshot, and freshness after waiting", async (context) => {
  await context.test("temp changed during wait", async () => {
    const fs = atomicFs([undefined, atomicFailure(), undefined]);
    let control;
    control = atomicPublisher(fs, { wait: async (ms) => {
      control.setNow(control.now() + ms);
      const temporary = [...fs.files.keys()].find((entry) => entry.endsWith(".tmp"));
      fs.setJson(temporary, atomicManifest(99));
    } });
    await control.publisher.publish(atomicManifest(1));
    await assert.rejects(control.publisher.publish(atomicManifest(2)),
      (error) => error instanceof ControllerError && error.kind === "outcome_unknown");
    assert.equal(fs.renames.length, 2);
    assert.equal(fs.json("C:\\evidence\\resource-manifest.json").revision, 1);
    assert.equal([...fs.files.keys()].filter((entry) => entry.endsWith(".tmp")).length, 1);
  });

  await context.test("target snapshot changed during wait", async () => {
    const fs = atomicFs([undefined, atomicFailure(), undefined]);
    let control;
    control = atomicPublisher(fs, { wait: async (ms) => {
      control.setNow(control.now() + ms);
      fs.touch("C:\\evidence\\resource-manifest.json");
    } });
    await control.publisher.publish(atomicManifest(1));
    await assert.rejects(control.publisher.publish(atomicManifest(2)),
      (error) => error instanceof ControllerError && error.kind === "outcome_unknown");
    assert.equal(fs.renames.length, 2);
    assert.equal(fs.json("C:\\evidence\\resource-manifest.json").revision, 1);
  });

  await context.test("target custody crosses freshness cutoff", async () => {
    const fs = atomicFs([undefined, atomicFailure(), undefined]);
    const target = fs.key("C:\\evidence\\resource-manifest.json");
    let control, afterWait = false;
    const openWithSlowTarget = async (file, flag, mode) => {
      if (afterWait && flag === "r" && fs.key(file) === target) control.setNow(1_000);
      return fs.open(file, flag, mode);
    };
    control = atomicPublisher(fs, {
      open: openWithSlowTarget,
      maxManifestAgeMs: 1_000,
      wait: async () => { control.setNow(400); afterWait = true; },
    });
    await control.publisher.publish(atomicManifest(1));
    await assert.rejects(control.publisher.publish(atomicManifest(2)),
      (error) => error.code === "EPERM" && error.syscall === "rename");
    assert.equal(fs.renames.length, 2);
    assert.equal(fs.json("C:\\evidence\\resource-manifest.json").revision, 1);
  });
});

test("manifest replacement stops at existing freshness and host bounds without extending time", async () => {
  const fs = atomicFs([undefined, atomicFailure(), atomicFailure(), atomicFailure()]);
  const control = atomicPublisher(fs, { heartbeatMs: 400, maxManifestAgeMs: 1_000 });
  await control.publisher.publish(atomicManifest(1));
  await assert.rejects(control.publisher.publish(atomicManifest(2)),
    (error) => error.code === "EPERM" && error.syscall === "rename");
  assert.equal(control.now(), 1_000);
  assert.equal(fs.renames.length, 4);
  assert.equal(fs.json("C:\\evidence\\resource-manifest.json").revision, 1);
  assert.equal([...fs.files.keys()].some((name) => name.endsWith(".tmp")), false);

  const deadlineFs = atomicFs([undefined, atomicFailure()]);
  const deadline = atomicPublisher(deadlineFs, { absoluteDeadlineMs: 50,
    wait: async () => { deadline.setNow(50); } });
  await deadline.publisher.publish(atomicManifest(1));
  await assert.rejects(deadline.publisher.publish(atomicManifest(2)),
    (error) => error.code === "EPERM" && error.syscall === "rename");
  assert.equal(deadlineFs.renames.length, 2);
});

test("abort stops replacement retry while an aborted teardown retains one bounded attempt", async () => {
  const fs = atomicFs([undefined, atomicFailure(), undefined]);
  let control;
  control = atomicPublisher(fs, { wait: async () => { control.abort.abort(); } });
  await control.publisher.publish(atomicManifest(1));
  await assert.rejects(control.publisher.publish(atomicManifest(2)),
    (error) => error.code === "EPERM" && error.syscall === "rename");
  assert.equal(fs.renames.length, 2);
  await control.publisher.publish(atomicManifest(3, "teardown"), { allowAbortedFirstAttempt: true });
  assert.equal(fs.renames.length, 3);
  assert.equal(fs.json("C:\\evidence\\resource-manifest.json").revision, 3);
  control.publisher.stop();
  await assert.rejects(control.publisher.publish(atomicManifest(4, "complete"), { allowAbortedFirstAttempt: true }),
    (error) => error instanceof ControllerError && error.kind === "censored");
  assert.equal(fs.renames.length, 3);
});

test("replacement custody contradictions become outcome_unknown and never retry", async (context) => {
  const scenarios = {
    target_changed({ api, destinationKey }) {
      api.setJson(destinationKey, atomicManifest(99));
      throw atomicFailure();
    },
    temp_lost({ api, sourceKey }) {
      api.remove(sourceKey);
      throw atomicFailure();
    },
    temp_changed({ api, sourceKey }) {
      api.setJson(sourceKey, atomicManifest(99));
      throw atomicFailure();
    },
    target_unreadable({ api, destinationKey }) {
      api.unreadable.add(destinationKey);
      throw atomicFailure();
    },
    target_became_intended({ api, sourceKey, destinationKey }) {
      api.files.set(destinationKey, api.files.get(sourceKey));
      api.files.delete(sourceKey);
      throw atomicFailure();
    },
  };
  for (const [name, action] of Object.entries(scenarios)) {
    await context.test(name, async () => {
      const fs = atomicFs([undefined, action]);
      const { publisher } = atomicPublisher(fs);
      await publisher.publish(atomicManifest(1));
      await assert.rejects(publisher.publish(atomicManifest(2)),
        (error) => error instanceof ControllerError && error.kind === "outcome_unknown");
      assert.equal(fs.renames.length, 2);
      if (name === "temp_changed") {
        assert.equal([...fs.files.keys()].filter((entry) => entry.endsWith(".tmp")).length, 1);
      }
    });
  }
});

test("initial, non-Windows, and non-EPERM replacement failures are one-shot", async (context) => {
  await context.test("initial", async () => {
    const fs = atomicFs([atomicFailure()]);
    const { publisher } = atomicPublisher(fs);
    await assert.rejects(publisher.publish(atomicManifest(1)), (error) => error.code === "EPERM");
    assert.equal(fs.renames.length, 1);
  });
  await context.test("non-Windows", async () => {
    const fs = atomicFs([undefined, atomicFailure()]);
    const { publisher } = atomicPublisher(fs, { platform: "linux" });
    await publisher.publish(atomicManifest(1));
    await assert.rejects(publisher.publish(atomicManifest(2)), (error) => error.code === "EPERM");
    assert.equal(fs.renames.length, 2);
  });
  await context.test("non-EPERM", async () => {
    const fs = atomicFs([undefined, atomicFailure("EACCES")]);
    const { publisher } = atomicPublisher(fs);
    await publisher.publish(atomicManifest(1));
    await assert.rejects(publisher.publish(atomicManifest(2)), (error) => error.code === "EACCES");
    assert.equal(fs.renames.length, 2);
  });
});

test("publisher outcome_unknown permanently fences later revisions", async () => {
  const unknownAfterRename = ({ api, sourceKey, destinationKey }) => {
    api.files.set(destinationKey, api.files.get(sourceKey));
    api.files.delete(sourceKey);
    throw atomicFailure();
  };
  const fs = atomicFs([unknownAfterRename]);
  const { publisher } = atomicPublisher(fs);
  let firstError;
  await assert.rejects(publisher.publish(atomicManifest(1)), (error) => {
    firstError = error;
    return error instanceof ControllerError && error.kind === "outcome_unknown";
  });
  await assert.rejects(publisher.publish(atomicManifest(2, "teardown"), {
    allowAbortedFirstAttempt: true,
  }), (error) => error === firstError);
  assert.equal(fs.renames.length, 1);
});

test("sampler publication is serialized, phase-stable, joined on close, and closed thereafter", async () => {
  const calls = [], first = deferred(), third = deferred(), thirdStarted = deferred();
  let active = 0, maximumActive = 0;
  const sampler = new ResourceSampler({ files: [], manifestPath: "C:\\evidence\\resource-manifest.json" },
    "serialization-control", new AbortController().signal, {
      atomicWrite: async (_file, manifest) => {
        active += 1;
        maximumActive = Math.max(maximumActive, active);
        calls.push(manifest);
        if (calls.length === 1) await first.promise;
        if (calls.length === 3) { thirdStarted.resolve(); await third.promise; }
        active -= 1;
      },
    });
  const warm = sampler.setPhase("warm");
  const steady = sampler.setPhase("steady");
  first.resolve();
  await Promise.all([warm, steady]);
  assert.deepEqual(calls.map((row) => [row.revision, row.phase]), [[1, "warm"], [2, "steady"]]);
  assert.equal(maximumActive, 1);
  const teardown = sampler.setPhase("teardown");
  await thirdStarted.promise;
  let closeSettled = false;
  const close = sampler.close().then(() => { closeSettled = true; });
  await Promise.resolve();
  assert.equal(closeSettled, false);
  third.resolve();
  await Promise.all([teardown, close]);
  assert.equal(closeSettled, true);
  await assert.rejects(sampler.setPhase("complete"),
    (error) => error instanceof ControllerError && error.kind === "censored"
      && error.message === "resource sampler publication stopped for owned close");
  assert.equal(calls.length, 3);
});

test("sampler drops queued work after abort but permits one serialized teardown publication", async () => {
  const abort = new AbortController();
  const firstStarted = deferred(), releaseFirst = deferred();
  const calls = [];
  const sampler = new ResourceSampler({ files: [], manifestPath: "C:\\evidence\\resource-manifest.json" },
    "queued-abort-control", abort.signal, {
      atomicWrite: async (_file, manifest) => {
        calls.push(manifest);
        if (calls.length === 1) {
          firstStarted.resolve();
          await releaseFirst.promise;
          throw atomicFailure();
        }
      },
    });
  const first = sampler.setPhase("warm");
  await firstStarted.promise;
  const queued = sampler.setPhase("steady");
  abort.abort();
  releaseFirst.resolve();
  await assert.rejects(first, (error) => error.code === "EPERM");
  await assert.rejects(queued,
    (error) => error instanceof ControllerError && error.kind === "censored");
  assert.deepEqual(calls.map((row) => [row.revision, row.phase]), [[1, "warm"]]);
  await sampler.setPhase("teardown");
  assert.deepEqual(calls.map((row) => [row.revision, row.phase]), [[1, "warm"], [2, "teardown"]]);
  await sampler.close();
});

test("sampler outcome_unknown fences queued and teardown publications before caller abort", async () => {
  const unknown = new ControllerError("atomic custody uncertain", "outcome_unknown");
  const firstStarted = deferred(), releaseFirst = deferred();
  const calls = [];
  const sampler = new ResourceSampler({ files: [], manifestPath: "C:\\evidence\\resource-manifest.json" },
    "queued-unknown-control", new AbortController().signal, {
      atomicWrite: async (_file, manifest) => {
        calls.push(manifest);
        firstStarted.resolve();
        await releaseFirst.promise;
        throw unknown;
      },
    });
  const first = sampler.setPhase("warm");
  const firstCheck = assert.rejects(first, (error) => error === unknown);
  await firstStarted.promise;
  const queued = sampler.setPhase("steady");
  const queuedCheck = assert.rejects(queued, (error) => error === unknown);
  releaseFirst.resolve();
  await Promise.all([firstCheck, queuedCheck]);
  assert.deepEqual(calls.map((row) => [row.revision, row.phase]), [[1, "warm"]]);
  await assert.rejects(sampler.setPhase("teardown"), (error) => error === unknown);
  assert.equal(calls.length, 1);
  await sampler.close();
});

test("normal close owns a queued heartbeat refusal without creating a sampler violation", async () => {
  const control = await heartbeatCloseControl();
  await control.sampler.setPhase("complete");
  control.tick();
  await control.heartbeatStarted.promise;
  control.tick();
  await control.sampler.acceptObservation({
    kind: "terminal", success: true, observedRequiredExited: true,
  });
  control.child.exitCode = 0;
  control.child.stdout.end();
  const closing = control.sampler.close();
  control.releaseHeartbeat.resolve();
  await closing;
  assert.deepEqual(control.writes.map((row) => row.revision), [1, 2, 3, 4]);
  assert.equal(control.violations(), 0);
});

test("normal close retains genuine heartbeat failure and ambiguity", async (context) => {
  for (const [name, failure] of [
    ["failure", atomicFailure("EIO", "write")],
    ["unknown", new ControllerError("heartbeat custody uncertain", "outcome_unknown")],
  ]) {
    await context.test(name, async () => {
      const control = await heartbeatCloseControl(failure);
      await control.sampler.setPhase("complete");
      control.tick();
      await control.heartbeatStarted.promise;
      await control.sampler.acceptObservation({
        kind: "terminal", success: true, observedRequiredExited: true,
      });
      control.child.exitCode = 0;
      control.child.stdout.end();
      const closing = control.sampler.close();
      const closeCheck = assert.rejects(closing, (error) => error === failure);
      control.releaseHeartbeat.resolve();
      await closeCheck;
      assert.deepEqual(control.writes.map((row) => row.revision), [1, 2, 3, 4]);
      assert.equal(control.violations(), 1);
    });
  }
});

test("external work cancellation racing close is not treated as owned close cancellation", async () => {
  const abort = new AbortController();
  const control = await heartbeatCloseControl(null, abort.signal, 3);
  control.tick();
  await control.heartbeatStarted.promise;
  control.tick();
  abort.abort();
  control.child.exitCode = 0;
  control.child.stdout.end();
  const closeCheck = assert.rejects(control.sampler.close(),
    (error) => error instanceof ControllerError && error.kind === "censored");
  control.releaseHeartbeat.resolve();
  await closeCheck;
  assert.deepEqual(control.writes.map((row) => row.revision), [1, 2, 3]);
  assert.equal(control.violations(), 1);
});

test("a missing sampler heartbeat cancels held work at the declared freshness bound", async () => {
  const cancellation = new AbortController();
  let violation;
  let violationEvidence;
  const sampler = new ResourceSampler({ files: [] }, "freshness-control", cancellation.signal, {
    onViolation: (error, evidence) => {
      violation = error;
      violationEvidence = evidence;
      cancellation.abort();
    },
  });
  sampler.phase = "steady";
  sampler.freshnessMs = samplerFreshnessMs({ sampleIntervalMs: 1, maxSweepMs: 1 });
  const held = new Promise((resolve) => cancellation.signal.addEventListener("abort", resolve, { once: true }));
  await sampler.acceptObservation({ kind: "sample", decision: "Continue", complete: true, reasons: [] });
  await held;
  assert.equal(violation?.kind, "censored");
  assert.match(violation?.message, /sampleIntervalMs \+ maxSweepMs/);
  assert.equal(violationEvidence?.lifecycle_stage, "sampler_freshness");
  await assert.rejects(sampler.close(), /sampleIntervalMs \+ maxSweepMs/);
});

function manifestFixture(root, topologyDigest) {
  const peers = Array.from({ length: 4 }, (_, index) => ({
    localAlias: `node-${index}`,
    expectedDeviceId: publicIds[index],
    args: {
      binary: path.join(root, "myownmesh.exe"),
      home: path.join(root, `home-${index}`),
      config: path.join(root, `config-${index}.json`),
      grantFile: path.join(root, `grant-${index}.txt`),
      output: path.join(root, `peer-${index}.jsonl`),
      durationMs: 70_000,
      reuseHome: true,
    },
  }));
  return {
    schema: "myownmesh-live-scale-host/v1",
    runId: "scale-10-control",
    physicalHost: "host-a",
    stage: 10,
    aggregateDeadlineMs: 60_000,
    teardownReserveMs: 10_000,
    maxConcurrentStarts: 1,
    maxConcurrentCommands: 1,
    topologyPlanPath: path.join(root, "topology.json"),
    topologyPlanSha256: topologyDigest,
    hostGrantLedger: Object.fromEntries(GRANT_DIMENSIONS.map((name) => [name, "10"])),
    peers,
    sampler: {
      required: true,
      scriptPath: path.join(root, "live-device-resources.ps1"),
      policyPath: path.join(root, "resource-policy.json"),
      manifestPath: path.join(root, "resource-manifest.json"),
      heartbeatMs: 100,
      files: peers.map((peer) => ({ nodeAlias: peer.localAlias,
        path: path.join(peer.args.home, "semantic.sqlite3"), kind: "main" })),
    },
  };
}

class FakeSampler {
  async start() {}
  async gate() { return { decision: "Continue" }; }
  async setPhase() {}
  async registerDaemon(_alias, session) {
    await session.pinDaemonCreationIdentity("638612345678901234");
    return "638612345678901234";
  }
  async complete() { return { kind: "terminal", success: true, observedRequiredExited: true }; }
  async close() {}
}

function codedSampler(error, evidenceStage = "sampler_manifest_heartbeat") {
  return class extends ResourceSampler {
    constructor(config, runId, signal, hooks) {
      super(config, runId, signal, hooks);
      this.testHooks = hooks;
    }
    async start() {
      this.testHooks.onViolation(error, boundedHostErrorEvidence(error, evidenceStage));
    }
    async gate() { return { decision: "Continue" }; }
    async setPhase() {}
    async registerDaemon() { throw new Error("aborted startup must not register a daemon"); }
    async complete() { return { kind: "terminal", success: true, observedRequiredExited: true }; }
    async close() {}
  };
}

function triggeredSampler(error, triggerPhase = null, onInstance = () => {}) {
  return class extends ResourceSampler {
    constructor(config, runId, signal, hooks) {
      super(config, runId, signal, hooks);
      this.testHooks = hooks;
      this.triggered = false;
      onInstance(this);
    }
    async start() {}
    async gate() { return { decision: "Continue" }; }
    async setPhase(phase) {
      if (phase === triggerPhase) this.trigger();
    }
    trigger() {
      if (this.triggered) return;
      this.triggered = true;
      const evidence = boundedHostErrorEvidence(error, "sampler_manifest_heartbeat");
      this.testHooks.onViolation(error, evidence, evidence);
    }
    async registerDaemon(_alias, session) {
      await session.pinDaemonCreationIdentity("638612345678901234");
      return "638612345678901234";
    }
    async complete() { return { kind: "terminal", success: true, observedRequiredExited: true }; }
    async close() {}
  };
}

function closeObservedSessions(log, closeStarted, afterClose = () => {}) {
  const basic = fakeSessions(log);
  return (args, options) => {
    const session = basic(args, options);
    const close = session.close.bind(session);
    session.close = async () => {
      closeStarted();
      afterClose();
      return close();
    };
    return session;
  };
}

test("a coded sampler failure is retained without its message or paths", async () => {
  const files = await caseFiles([{ sequence: 1, kind: "complete" }]);
  const samplerError = Object.assign(new Error("SECRET manifest path C:/private/manifest.json"), {
    name: "SECRET_NAME",
    code: "EPERM",
    syscall: "rename",
    errno: -4048,
    path: "C:/private/manifest.json",
  });
  await assert.rejects(
    runScaleHost(
      { manifest: files.manifestPath, commands: files.commandPath, output: files.outputPath },
      { createPeerSession: () => { throw new Error("startup continued after violation"); },
        ResourceSampler: codedSampler(samplerError), emitLifecycle: async () => {} },
    ),
    (error) => error === samplerError,
  );
  const raw = await readFile(files.outputPath, "utf8");
  const evidence = raw.trim().split("\n").map(JSON.parse);
  const violation = evidence.find((row) => row.type === "resource_violation");
  const terminal = evidence.find((row) => row.type === "host_terminal");
  assert.deepEqual(violation.error, {
    name: "Error", kind: "failed", lifecycle_stage: "sampler_manifest_heartbeat",
    os_code: "EPERM", syscall: "rename", errno: -4048,
  });
  assert.deepEqual(terminal.error, violation.error);
  assert.deepEqual(terminal.first_sampler_violation, violation.error);
  assert.equal(terminal.sampler_violation_capture_error, null);
  assert.doesNotMatch(raw, /SECRET|private|manifest\.json/);
});

test("sampler evidence capture failure is retained and unknown dominates", async () => {
  const files = await caseFiles([{ sequence: 1, kind: "complete" }]);
  const samplerError = Object.assign(new Error("SECRET sampler"), {
    code: "EPERM", syscall: "rename", errno: -4048, path: "C:/secret",
  });
  const captureError = Object.assign(
    new ControllerError("SECRET capture", "outcome_unknown"),
    { code: "EPIPE", syscall: "write", errno: -32, path: "C:/secret-output" },
  );
  await assert.rejects(
    runScaleHost(
      { manifest: files.manifestPath, commands: files.commandPath, output: files.outputPath },
      {
        createPeerSession: () => { throw new Error("startup continued after violation"); },
        ResourceSampler: codedSampler(samplerError),
        emitLifecycle: async (row) => {
          if (row.type === "resource_violation") throw captureError;
        },
      },
    ),
    (error) => error === captureError && error.kind === "outcome_unknown",
  );
  const raw = await readFile(files.outputPath, "utf8");
  const terminal = raw.trim().split("\n").map(JSON.parse)
    .find((row) => row.type === "host_terminal");
  assert.equal(terminal.status, "outcome_unknown");
  assert.deepEqual(terminal.error, {
    name: "ControllerError", kind: "outcome_unknown",
    lifecycle_stage: "sampler_violation_capture", os_code: "EPIPE", syscall: "write", errno: -32,
  });
  assert.deepEqual(hostProcessFailureRecord(captureError).error, terminal.error);
  assert.equal(terminal.first_sampler_violation.os_code, "EPERM");
  assert.deepEqual(terminal.sampler_violation_capture_error, terminal.error);
  assert.doesNotMatch(raw, /SECRET|secret-output|C:\/secret/);
});

test("held violation evidence never sits ahead of owned peer teardown", async () => {
  const files = await caseFiles([
    { sequence: 1, kind: "phase", phase: "held", commands: [
      { peer: "node-0", command: { id: "held", action: "rpc", request: { op: "held" } },
        acceptedStatuses: ["acknowledged"] },
    ] },
    { sequence: 2, kind: "complete" },
  ]);
  const samplerError = Object.assign(new Error("hidden"), {
    code: "EPERM", syscall: "rename", errno: -4048,
  });
  let samplerInstance;
  let releaseCapture;
  const heldCapture = new Promise((resolve) => { releaseCapture = resolve; });
  let observeClose;
  const closeStarted = new Promise((resolve) => { observeClose = resolve; });
  let captureReleased = false;
  const log = [];
  const baseSessions = closeObservedSessions(log, observeClose);
  const createHeldSession = (args, options) => {
    const session = baseSessions(args, options);
    const execute = session.execute.bind(session);
    session.execute = async (command) => {
      if (command.request?.op !== "held") return execute(command);
      return new Promise((resolve) => {
        options.signal.addEventListener("abort", () => resolve({
          id: command.id, action: "rpc", status: "failed",
        }), { once: true });
        queueMicrotask(() => samplerInstance.trigger());
      });
    };
    return session;
  };
  const running = runScaleHost(
    { manifest: files.manifestPath, commands: files.commandPath, output: files.outputPath },
    {
      createPeerSession: createHeldSession,
      ResourceSampler: triggeredSampler(samplerError, null, (instance) => { samplerInstance = instance; }),
      emitLifecycle: async (row) => {
        if (row.type === "resource_violation") await heldCapture;
      },
    },
  );
  await closeStarted;
  assert.equal(captureReleased, false);
  releaseCapture();
  captureReleased = true;
  await assert.rejects(running, (error) => error === samplerError);
  assert.equal(log.filter((row) => row.startsWith("close:")).length, 4);
});

test("a teardown violation joins delayed unknown capture before terminal status", async () => {
  const files = await caseFiles([{ sequence: 1, kind: "complete" }]);
  const samplerError = Object.assign(new Error("hidden"), {
    code: "EPERM", syscall: "rename", errno: -4048,
  });
  const captureError = Object.assign(
    new ControllerError("hidden", "outcome_unknown"),
    { code: "EPIPE", syscall: "write", errno: -32 },
  );
  let rejectCapture;
  const heldCapture = new Promise((_, reject) => { rejectCapture = reject; });
  let observeCaptureEntry;
  const captureEntered = new Promise((resolve) => { observeCaptureEntry = resolve; });
  let observeClose;
  const closeStarted = new Promise((resolve) => { observeClose = resolve; });
  const log = [];
  const running = runScaleHost(
    { manifest: files.manifestPath, commands: files.commandPath, output: files.outputPath },
    {
      createPeerSession: closeObservedSessions(log, observeClose),
      ResourceSampler: triggeredSampler(samplerError, "teardown"),
      emitLifecycle: async (row) => {
        if (row.type === "resource_violation") {
          observeCaptureEntry();
          await heldCapture;
        }
      },
    },
  );
  const ownedRunning = running.then(
    (value) => ({ value }),
    (error) => ({ error }),
  );
  await Promise.all([closeStarted, captureEntered]);
  rejectCapture(captureError);
  const outcome = await ownedRunning;
  assert.equal(outcome.error, captureError);
  assert.equal(outcome.error.kind, "outcome_unknown");
  const evidence = (await readFile(files.outputPath, "utf8")).trim().split("\n").map(JSON.parse);
  const terminal = evidence.find((row) => row.type === "host_terminal");
  assert.equal(terminal.status, "outcome_unknown");
  assert.equal(terminal.first_sampler_violation.os_code, "EPERM");
  assert.equal(terminal.sampler_violation_capture_error.os_code, "EPIPE");
  assert.equal(log.filter((row) => row.startsWith("close:")).length, 4);
});

test("a settled unknown capture survives peer closes consuming the host deadline", async () => {
  const files = await caseFiles([{ sequence: 1, kind: "complete" }]);
  const samplerError = Object.assign(new Error("hidden"), {
    code: "EPERM", syscall: "rename", errno: -4048,
  });
  const captureError = Object.assign(
    new ControllerError("hidden", "outcome_unknown"),
    { code: "EPIPE", syscall: "write", errno: -32 },
  );
  let now = 0;
  let observeCaptureEntry;
  const captureEntered = new Promise((resolve) => { observeCaptureEntry = resolve; });
  let observeAllCloses;
  const allClosesStarted = new Promise((resolve) => { observeAllCloses = resolve; });
  let releaseCloses;
  const closeGate = new Promise((resolve) => { releaseCloses = resolve; });
  let closeCount = 0;
  const log = [];
  const baseSessions = fakeSessions(log);
  const heldCloseSessions = (args, options) => {
    const session = baseSessions(args, options);
    const close = session.close.bind(session);
    session.close = async () => {
      closeCount += 1;
      if (closeCount === 4) observeAllCloses();
      await closeGate;
      now += 15_000;
      return close();
    };
    return session;
  };
  const running = runScaleHost(
    { manifest: files.manifestPath, commands: files.commandPath, output: files.outputPath },
    {
      monoMs: () => now,
      createPeerSession: heldCloseSessions,
      ResourceSampler: triggeredSampler(samplerError, "teardown"),
      emitLifecycle: async (row) => {
        if (row.type === "resource_violation") {
          observeCaptureEntry();
          throw captureError;
        }
      },
    },
  );
  const ownedRunning = running.then(
    (value) => ({ value }),
    (error) => ({ error }),
  );
  await Promise.all([captureEntered, allClosesStarted]);
  await new Promise((resolve) => setImmediate(resolve));
  releaseCloses();
  const outcome = await ownedRunning;
  assert.equal(outcome.error, captureError);
  assert.equal(outcome.error.kind, "outcome_unknown");
  assert.equal(now, 60_000);
  const evidence = (await readFile(files.outputPath, "utf8")).trim().split("\n").map(JSON.parse);
  const terminal = evidence.find((row) => row.type === "host_terminal");
  assert.equal(terminal.status, "outcome_unknown");
  assert.equal(terminal.error.os_code, "EPIPE");
  assert.equal(terminal.sampler_violation_capture_error.os_code, "EPIPE");
  assert.equal(log.filter((row) => row.startsWith("close:")).length, 4);
});

test("an unresolved violation sink is censored only after owned peers exit", async () => {
  const files = await caseFiles([{ sequence: 1, kind: "complete" }]);
  const samplerError = Object.assign(new Error("hidden"), {
    code: "EPERM", syscall: "rename", errno: -4048,
  });
  let now = 0;
  let closes = 0;
  const log = [];
  await assert.rejects(
    runScaleHost(
      { manifest: files.manifestPath, commands: files.commandPath, output: files.outputPath },
      {
        monoMs: () => now,
        createPeerSession: closeObservedSessions(log, () => { closes += 1; }, () => { now = 60_000; }),
        ResourceSampler: triggeredSampler(samplerError, "teardown"),
        emitLifecycle: async (row) => {
          if (row.type === "resource_violation") await new Promise(() => {});
        },
      },
    ),
    (error) => error === samplerError,
  );
  assert.equal(closes, 4);
  const evidence = (await readFile(files.outputPath, "utf8")).trim().split("\n").map(JSON.parse);
  const terminal = evidence.find((row) => row.type === "host_terminal");
  assert.equal(terminal.status, "failed");
  assert.equal(terminal.sampler_violation_capture_error.kind, "censored");
  assert.equal(terminal.sampler_violation_capture_error.lifecycle_stage, "sampler_violation_capture");
});

async function caseFiles(journalRows) {
  const root = await mkdtemp(path.join(os.tmpdir(), "myownmesh-scale-host-"));
  const topologyBase = {
    schema: "myownmesh.scale-topology.v1",
    stage: 10,
    nodes: Array.from({ length: 10 }, (_, index) => ({
      local_alias: `node-${index}`,
      physical_host: index < 4 ? "host-a" : index < 7 ? "host-b" : "host-c",
      device_id: publicIds[index],
      network_config: { id: "scale", network_id: "scale-10", kind: "open" },
    })),
  };
  const topology = { ...topologyBase,
    plan_sha256: createHash("sha256").update(JSON.stringify(topologyBase)).digest("hex") };
  const topologyBytes = Buffer.from(`${JSON.stringify(topology)}\n`);
  const topologyDigest = createHash("sha256").update(topologyBytes).digest("hex");
  const manifest = manifestFixture(root, topologyDigest);
  await writeFile(manifest.topologyPlanPath, topologyBytes);
  for (const [index, peer] of manifest.peers.entries()) {
    await writeFile(peer.args.grantFile, grantText());
    await writeFile(peer.args.config, JSON.stringify({
      auto_update: { enabled: false, auto_apply: "none" },
      daemon: { control_socket: `\\\\.\\pipe\\myownmesh-live-scale-${index}` },
      networks: [{ id: "scale", network_id: "scale-10", kind: "open" }],
    }));
  }
  const manifestPath = path.join(root, "manifest.json");
  const commandPath = path.join(root, "commands.jsonl");
  const outputPath = path.join(root, "host.jsonl");
  await writeFile(manifestPath, JSON.stringify(manifest));
  await writeFile(commandPath, journalRows.map((row) => JSON.stringify(row)).join("\n") + "\n");
  return { root, manifestPath, commandPath, outputPath };
}

function fakeSessions(log, unknownId = null, identityMode = "valid") {
  let nextPid = 1000;
  return (args, options) => {
    const pid = nextPid++;
    const alias = `node-${pid - 1000}`;
    let running = true;
    log.push(`start:${alias}`);
    return {
      ready: (async () => ({ daemonPid: pid, binarySha256: "a",
        configSha256: createHash("sha256").update(await readFile(args.config)).digest("hex"),
        grantSha256: createHash("sha256").update(await readFile(args.grantFile)).digest("hex") }))(),
      daemonIsRunning: () => running,
      async pinDaemonCreationIdentity() { assert.equal(running, true); },
      async execute(command) {
        log.push(`execute:${alias}:${command.id}`);
        const result = command.request?.op === "status"
          ? { id: command.id, action: "rpc", status: "acknowledged", result: { ok: true,
              data: { device_id: `${publicIds[pid - 1000]}-DISPLAY` } } }
          : command.request?.op === "identity_show"
            ? { id: command.id, action: "rpc", status: "acknowledged", result: { ok: true,
                data: identityMode === "missing"
                  ? { device_id: `${publicIds[pid - 1000]}-DISPLAY` }
                  : { pubkey: identityMode === "wrong" ? publicIds[(pid - 999) % 10] : publicIds[pid - 1000],
                      device_id: `${publicIds[pid - 1000]}-DISPLAY` } } }
          : { id: command.id, action: command.action,
              status: command.id.includes(unknownId ?? "\u0000") ? "outcome_unknown" : "acknowledged" };
        await options.onRecord?.({ type: "fake", id: command.id });
        return result;
      },
      async close() { running = false; log.push(`close:${alias}`); return { status: "complete" }; },
    };
  };
}

test("one host owner starts its global-ten subset serially and completes phases automatically", async () => {
  const files = await caseFiles([
    { sequence: 1, kind: "phase", phase: "probe", commands: [
      { peer: "node-0", command: { id: "status", action: "rpc", request: { op: "status" } }, acceptedStatuses: ["acknowledged"] },
    ] },
    { sequence: 2, kind: "complete" },
  ]);
  const log = [];
  const clock = () => 123;
  let receivedSamplerHooks;
  class CapturingSampler extends FakeSampler {
    constructor(_config, _runId, _signal, hooks) {
      super();
      receivedSamplerHooks = hooks;
    }
  }
  const result = await runScaleHost(
    { manifest: files.manifestPath, commands: files.commandPath, output: files.outputPath },
    { monoMs: clock, createPeerSession: fakeSessions(log), ResourceSampler: CapturingSampler,
      samplerHooks: { monoMs: () => 999, absoluteDeadlineMs: -1 }, emitLifecycle: async () => {} },
  );
  assert.deepEqual(result, { status: "complete", sessions: 4, commands: 1 });
  assert.equal(receivedSamplerHooks.monoMs, clock);
  assert.equal(receivedSamplerHooks.absoluteDeadlineMs, 60_123);
  assert.equal(log.filter((row) => row.startsWith("start:")).length, 4);
  assert.equal(log.filter((row) => row.startsWith("close:")).length, 4);
  const evidence = await readFile(files.outputPath, "utf8");
  assert.match(evidence, /"type":"host_phase_terminal"/);
  assert.match(evidence, /"type":"host_terminal"/);
});

test("an unknown write stops later phases while every owned peer is closed", async () => {
  const files = await caseFiles([
    { sequence: 1, kind: "phase", phase: "write", commands: [
      { peer: "node-0", command: { id: "unknown", action: "rpc", request: { op: "mutate" } }, acceptedStatuses: ["acknowledged"] },
    ] },
    { sequence: 2, kind: "phase", phase: "must-not-run", commands: [
      { peer: "node-1", command: { id: "later", action: "rpc", request: { op: "mutate" } }, acceptedStatuses: ["acknowledged"] },
    ] },
    { sequence: 3, kind: "complete" },
  ]);
  const log = [];
  await assert.rejects(
    runScaleHost(
      { manifest: files.manifestPath, commands: files.commandPath, output: files.outputPath },
      { createPeerSession: fakeSessions(log, "unknown"), ResourceSampler: FakeSampler, emitLifecycle: async () => {} },
    ),
    (error) => error?.kind === "outcome_unknown",
  );
  assert.equal(log.some((row) => row.includes("later")), false);
  assert.equal(log.filter((row) => row.startsWith("close:")).length, 4);
});

test("an active StopTrial or stale-observation breach cancels held work before a later batch", async () => {
  for (const breach of ["stop", "stale"]) {
    const files = await caseFiles([
      { sequence: 1, kind: "phase", phase: "held", commands: [
        { peer: "node-0", command: { id: "held", action: "rpc", request: { op: "held" } }, acceptedStatuses: ["acknowledged"] },
        { peer: "node-1", command: { id: "later", action: "rpc", request: { op: "later" } }, acceptedStatuses: ["acknowledged"] },
      ] },
      { sequence: 2, kind: "complete" },
    ]);
    let samplerInstance;
    class BreachSampler extends ResourceSampler {
      constructor(config, runId, signal, hooks) {
        super(config, runId, signal, hooks);
        samplerInstance = this;
      }
      async start() {}
      async gate() { return { decision: "Continue" }; }
      async setPhase() {}
      async registerDaemon(_alias, session) {
        await session.pinDaemonCreationIdentity("638612345678901234");
        return "638612345678901234";
      }
      async complete() { return { kind: "terminal", success: true, observedRequiredExited: true }; }
      async close() {}
      breach() {
        const record = breach === "stop"
          ? { kind: "sample", decision: "StopTrial", complete: false, reasons: ["private_limit"] }
          : { kind: "sample", decision: "Freeze", complete: false, reasons: ["manifest_stale"] };
        this.phase = "steady";
        return this.acceptObservation(record);
      }
    }
    const log = [];
    let cancellationObserved = false;
    const basic = fakeSessions(log);
    const createHeldSession = (args, options) => {
      const session = basic(args, options);
      const execute = session.execute.bind(session);
      session.execute = async (command) => {
        if (command.request?.op !== "held") return execute(command);
        log.push(`execute:node-0:${command.id}`);
        return new Promise((resolve) => {
          options.signal.addEventListener("abort", () => {
            cancellationObserved = true;
            resolve({ id: command.id, action: "rpc", status: "failed" });
          }, { once: true });
          queueMicrotask(() => samplerInstance.breach());
        });
      };
      return session;
    };
    await assert.rejects(
      runScaleHost(
        { manifest: files.manifestPath, commands: files.commandPath, output: files.outputPath },
        { createPeerSession: createHeldSession, ResourceSampler: BreachSampler,
          emitLifecycle: async () => {} },
      ),
      /resource sampler/,
    );
    assert.equal(cancellationObserved, true);
    assert.equal(log.some((row) => row.includes("later")), false);
    assert.equal(log.filter((row) => row.startsWith("close:")).length, 4);
  }
});

test("an ambiguous in-flight send remains outcome_unknown when a guard breach cancels it", async () => {
  const files = await caseFiles([
    { sequence: 1, kind: "phase", phase: "held", commands: [
      { peer: "node-0", command: { id: "held", action: "rpc", request: { op: "held" } }, acceptedStatuses: ["acknowledged"] },
      { peer: "node-1", command: { id: "later", action: "rpc", request: { op: "later" } }, acceptedStatuses: ["acknowledged"] },
    ] },
    { sequence: 2, kind: "complete" },
  ]);
  let samplerInstance;
  class StopSampler extends ResourceSampler {
    constructor(config, runId, signal, hooks) {
      super(config, runId, signal, hooks);
      samplerInstance = this;
    }
    async start() {}
    async gate() { return { decision: "Continue" }; }
    async setPhase() {}
    async registerDaemon(_alias, session) {
      await session.pinDaemonCreationIdentity("638612345678901234");
      return "638612345678901234";
    }
    async complete() { return { kind: "terminal", success: true, observedRequiredExited: true }; }
    async close() {}
    breach() {
      const record = { kind: "sample", decision: "StopTrial", complete: false,
        reasons: ["working_set_limit"] };
      this.phase = "steady";
      return this.acceptObservation(record);
    }
  }
  const log = [];
  const basic = fakeSessions(log);
  const createAmbiguousSession = (args, options) => {
    const session = basic(args, options);
    const execute = session.execute.bind(session);
    session.execute = async (command) => {
      if (command.request?.op !== "held") return execute(command);
      return new Promise((resolve) => {
        options.signal.addEventListener("abort", () => resolve({
          id: command.id, action: "rpc", status: "outcome_unknown",
        }), { once: true });
        queueMicrotask(() => samplerInstance.breach());
      });
    };
    return session;
  };
  await assert.rejects(
    runScaleHost(
      { manifest: files.manifestPath, commands: files.commandPath, output: files.outputPath },
      { createPeerSession: createAmbiguousSession, ResourceSampler: StopSampler,
        emitLifecycle: async () => {} },
    ),
    (error) => error?.kind === "outcome_unknown",
  );
  assert.equal(log.some((row) => row.includes("later")), false);
  assert.equal(log.filter((row) => row.startsWith("close:")).length, 4);
});

test("a concurrent batch joins every started command and unknown dominates a sibling failure", async () => {
  const files = await caseFiles([
    { sequence: 1, kind: "phase", phase: "concurrent", commands: [
      { peer: "node-0", command: { id: "ordinary", action: "rpc", request: { op: "ordinary-failure" } }, acceptedStatuses: ["acknowledged"] },
      { peer: "node-1", command: { id: "ambiguous", action: "rpc", request: { op: "delayed-unknown" } }, acceptedStatuses: ["acknowledged"] },
    ] },
    { sequence: 2, kind: "phase", phase: "must-not-run", commands: [
      { peer: "node-2", command: { id: "later", action: "rpc", request: { op: "later" } }, acceptedStatuses: ["acknowledged"] },
    ] },
    { sequence: 3, kind: "complete" },
  ]);
  const manifest = JSON.parse(await readFile(files.manifestPath, "utf8"));
  manifest.maxConcurrentCommands = 2;
  await writeFile(files.manifestPath, JSON.stringify(manifest));
  const log = [];
  const basic = fakeSessions(log);
  const createConcurrentSession = (args, options) => {
    const session = basic(args, options);
    const execute = session.execute.bind(session);
    session.execute = async (command) => {
      if (command.request?.op === "ordinary-failure") {
        log.push("ordinary-failure-settled");
        throw new ControllerError("ordinary sibling failed");
      }
      if (command.request?.op === "delayed-unknown") {
        await new Promise((resolve) => setTimeout(resolve, 20));
        log.push("unknown-settled");
        return { id: command.id, action: "rpc", status: "outcome_unknown" };
      }
      return execute(command);
    };
    return session;
  };
  await assert.rejects(
    runScaleHost(
      { manifest: files.manifestPath, commands: files.commandPath, output: files.outputPath },
      { createPeerSession: createConcurrentSession, ResourceSampler: FakeSampler,
        emitLifecycle: async () => {} },
    ),
    (error) => error?.kind === "outcome_unknown",
  );
  const unknownSettledAt = log.indexOf("unknown-settled");
  const firstCloseAt = log.findIndex((entry) => entry.startsWith("close:"));
  assert.ok(unknownSettledAt >= 0 && firstCloseAt > unknownSettledAt);
  assert.equal(log.some((entry) => entry.includes("later")), false);
  assert.equal(log.filter((entry) => entry.startsWith("close:")).length, 4);
  const evidence = (await readFile(files.outputPath, "utf8")).trim().split("\n").map(JSON.parse);
  const commandRows = evidence.filter((row) => row.type === "host_command_result" && row.sequence === 1);
  assert.deepEqual(commandRows.map((row) => row.status).sort(), ["failed", "outcome_unknown"]);
});

test("external cancellation reaches the active peer and still closes the owned daemon", async () => {
  const files = await caseFiles([{ sequence: 1, kind: "complete" }]);
  const cancellation = new AbortController();
  class CancellingSampler extends FakeSampler {
    async registerDaemon(alias, session, ready) {
      const ticks = await super.registerDaemon(alias, session, ready);
      cancellation.abort();
      return ticks;
    }
  }
  const log = [];
  await assert.rejects(
    runScaleHost(
      { manifest: files.manifestPath, commands: files.commandPath, output: files.outputPath },
      { signal: cancellation.signal, createPeerSession: fakeSessions(log),
        ResourceSampler: CancellingSampler, emitLifecycle: async () => {} },
    ),
    /startup exceeded work deadline/,
  );
  assert.equal(log.filter((row) => row.startsWith("start:")).length, 1);
  assert.equal(log.filter((row) => row.startsWith("close:")).length, 1);
});

test("display identity alone or the wrong canonical pubkey cannot prove topology ownership", async () => {
  for (const mode of ["missing", "wrong"]) {
    const files = await caseFiles([{ sequence: 1, kind: "complete" }]);
    const log = [];
    await assert.rejects(
      runScaleHost(
        { manifest: files.manifestPath, commands: files.commandPath, output: files.outputPath },
        { createPeerSession: fakeSessions(log, null, mode), ResourceSampler: FakeSampler,
          emitLifecycle: async () => {} },
      ),
      /identity_show omitted a canonical pubkey|canonical identity did not match/,
    );
    assert.equal(log.filter((row) => row.startsWith("close:")).length, 1);
  }
});

test("manifest admits only the finite staircase and one-at-a-time startup", () => {
  const manifest = manifestFixture(path.resolve("C:/scale-test"), "0".repeat(64));
  assert.equal(validateManifest(manifest).maxConcurrentStarts, 1);
  assert.throws(() => validateManifest({ ...manifest, stage: 11 }), /stage must be one of/);
  assert.throws(() => validateManifest({ ...manifest, maxConcurrentStarts: 2 }), /maxConcurrentStarts=1/);
});
