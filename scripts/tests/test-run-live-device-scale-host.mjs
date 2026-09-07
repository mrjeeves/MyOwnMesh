import assert from "node:assert/strict";
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  ControllerError,
} from "../live-device-peer.mjs";
import {
  GRANT_DIMENSIONS,
  ResourceSampler,
  enforceHostGrantLedger,
  parseGrant,
  parseJournal,
  runScaleHost,
  samplerFreshnessMs,
  samplerObservationError,
  validateManifest,
} from "../run-live-device-scale-host.mjs";

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

test("a missing sampler heartbeat cancels held work at the declared freshness bound", async () => {
  const cancellation = new AbortController();
  let violation;
  const sampler = new ResourceSampler({ files: [] }, "freshness-control", cancellation.signal, {
    onViolation: (error) => { violation = error; cancellation.abort(); },
  });
  sampler.phase = "steady";
  sampler.freshnessMs = samplerFreshnessMs({ sampleIntervalMs: 1, maxSweepMs: 1 });
  const held = new Promise((resolve) => cancellation.signal.addEventListener("abort", resolve, { once: true }));
  await sampler.acceptObservation({ kind: "sample", decision: "Continue", complete: true, reasons: [] });
  await held;
  assert.equal(violation?.kind, "censored");
  assert.match(violation?.message, /sampleIntervalMs \+ maxSweepMs/);
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
  const result = await runScaleHost(
    { manifest: files.manifestPath, commands: files.commandPath, output: files.outputPath },
    { createPeerSession: fakeSessions(log), ResourceSampler: FakeSampler, emitLifecycle: async () => {} },
  );
  assert.deepEqual(result, { status: "complete", sessions: 4, commands: 1 });
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
