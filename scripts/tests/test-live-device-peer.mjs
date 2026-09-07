import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  ControllerError,
  EventHub,
  JsonLineConnection,
  JsonlWriter,
  RpcClient,
  classifyActionResult,
  classifyLifetimeResult,
  collectionDeadlineError,
  controlEndpoint,
  controllerStatus,
  createPeerSession,
  createPeerSessionTestHarness,
  createRpcContextAdapter,
  endpointProbeDisposition,
  mergeControllerError,
  monoMs,
  stopOwnedChild,
} from "../live-device-peer.mjs";

function memoryWriter() {
  const rows = [];
  let closed = false;
  return {
    rows,
    get closed() { return closed; },
    async append(row) {
      if (closed) throw new Error("writer already closed");
      rows.push(row);
    },
    async close() { closed = true; },
  };
}

async function listen(server, endpoint) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(endpoint, () => {
      server.removeListener("error", reject);
      resolve();
    });
  });
}

async function closeServer(server) {
  await new Promise((resolve) => server.close(resolve));
}

test("work cancellation interrupts a real held RPC while cleanup keeps a separate bounded path", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "myownmesh-peer-rpc-"));
  const endpoint = process.platform === "win32"
    ? `\\\\.\\pipe\\myownmesh-live-rpc-${process.pid}-${Date.now()}`
    : path.join(root, "rpc.sock");
  let requests = 0;
  let receivedHeld;
  const heldReceived = new Promise((resolve) => { receivedHeld = resolve; });
  const server = net.createServer((socket) => {
    let buffer = "";
    socket.setEncoding("utf8");
    socket.on("data", (chunk) => {
      buffer += chunk;
      for (;;) {
        const newline = buffer.indexOf("\n");
        if (newline < 0) break;
        const request = JSON.parse(buffer.slice(0, newline));
        buffer = buffer.slice(newline + 1);
        requests += 1;
        if (request.op === "held") receivedHeld();
        else socket.write(`${JSON.stringify({ ok: true, data: { op: request.op } })}\n`);
      }
    });
  });
  await listen(server, endpoint);
  const transport = new AbortController();
  const work = new AbortController();
  const client = new RpcClient(endpoint, monoMs() + 5_000, transport.signal);
  try {
    const positive = await client.rpc({ op: "positive" }, 1_000, work.signal);
    assert.deepEqual(positive, { ok: true, data: { op: "positive" } });
    const pending = client.rpc({ op: "held" }, 5_000, work.signal);
    await heldReceived;
    work.abort();
    await assert.rejects(
      Promise.race([
        pending,
        new Promise((_, reject) => setTimeout(() => reject(new Error("abort was not prompt")), 500)),
      ]),
      (error) => error?.kind === "outcome_unknown",
    );
    assert.equal(requests, 2);
    const cleanup = await client.rpc({ op: "cleanup" }, 1_000);
    assert.deepEqual(cleanup, { ok: true, data: { op: "cleanup" } });
    assert.equal(requests, 3);
  } finally {
    client.close();
    transport.abort();
    await closeServer(server);
    await rm(root, { recursive: true, force: true });
  }
});

test("a cancellation during an attempted IPC write is unknown and is never retried", async () => {
  const socket = new EventEmitter();
  let writes = 0;
  socket.write = () => {
    writes += 1;
    return true;
  };
  socket.destroy = () => socket.emit("close");
  const connection = new JsonLineConnection(socket);
  const work = new AbortController();
  const pending = connection.send({ op: "write" }, 5_000, work.signal);
  work.abort();
  await assert.rejects(pending, (error) => error?.kind === "outcome_unknown");
  assert.equal(writes, 1);
  connection.close();
});

test("a cancelled queued write is refused before touching the socket", async () => {
  const socket = new EventEmitter();
  let writes = 0;
  socket.write = () => { writes += 1; };
  socket.destroy = () => socket.emit("close");
  const connection = new JsonLineConnection(socket);
  const work = new AbortController();
  work.abort();
  await assert.rejects(
    connection.send({ op: "must-not-send" }, 5_000, work.signal),
    (error) => error?.kind === "failed" && /before it was attempted/.test(error.message),
  );
  assert.equal(writes, 0);
  connection.close();
});

test("returned and thrown unknown outcomes survive a failing result capture", async () => {
  for (const mode of ["returned", "thrown"]) {
    const writer = memoryWriter();
    let rpcCalls = 0;
    const { session, child } = createPeerSessionTestHarness({
      writer,
      rpc: async () => {
        rpcCalls += 1;
        if (mode === "thrown") {
          throw new ControllerError("mutating request outcome is unknown", "outcome_unknown");
        }
        return { data: { malformed: true } };
      },
      onRecord: async (row) => {
        if (row.type === "command_result") throw new Error("result capture failed");
      },
    });
    await assert.rejects(
      session.execute({ id: `capture-${mode}`, action: "rpc", request: { op: "mutate" } }),
      (error) => {
        assert.equal(error?.kind, "outcome_unknown");
        assert.equal(error?.result?.command_record?.status, "outcome_unknown");
        assert.match(error?.result?.capture_error?.message, /result capture failed/);
        return true;
      },
    );
    assert.equal(rpcCalls, 1);
    assert.equal(writer.rows.some((row) => row.type === "command_result" &&
      row.status === "outcome_unknown"), true);
    child.exitCode = 0;
    await assert.rejects(session.close(), (error) => error?.kind === "outcome_unknown");
    assert.equal(writer.closed, true);
  }
});

test("close owns held start capture and no released or rejected start dispatches late work", async () => {
  for (const rejectStart of [false, true]) {
    const writer = memoryWriter();
    let rpcCalls = 0;
    let enteredStart;
    let releaseStart;
    const startEntered = new Promise((resolve) => { enteredStart = resolve; });
    const heldStart = new Promise((resolve, reject) => {
      releaseStart = () => rejectStart ? reject(new Error("start capture rejected")) : resolve();
    });
    const { session, child } = createPeerSessionTestHarness({
      writer,
      rpc: async () => {
        rpcCalls += 1;
        return { ok: true, data: {} };
      },
      onRecord: async (row) => {
        if (row.type === "command_started") {
          enteredStart();
          await heldStart;
        }
      },
    });
    const execution = session.execute({
      id: `held-start-${rejectStart}`,
      action: "rpc",
      request: { op: "must-not-dispatch" },
    });
    await startEntered;
    child.exitCode = 0;
    let closeSettled = false;
    const closeObserved = session.close().then(
      (value) => ({ value }),
      (error) => ({ error }),
    ).finally(() => { closeSettled = true; });
    await Promise.resolve();
    assert.equal(closeSettled, false);
    releaseStart();
    if (rejectStart) {
      await assert.rejects(execution, /start capture rejected/);
    } else {
      const record = await execution;
      assert.equal(record.status, "failed");
    }
    const closed = await closeObserved;
    assert.ok(closed.error);
    assert.equal(controllerStatus(closed.error), rejectStart ? "failed" : "censored");
    assert.equal(rpcCalls, 0);
    assert.equal(writer.rows.some((row) => row.type === "command_result"), true);
    assert.equal(writer.rows.at(-1).type, "controller_terminal");
    assert.equal(writer.rows.at(-1).status, rejectStart ? "failed" : "censored");
    assert.equal(writer.closed, true);
  }
});

test("import-safe peer sessions refuse an unbounded lifetime before launch", () => {
  assert.throws(
    () => createPeerSession({ durationMs: 24 * 60 * 60 * 1000 + 1 }),
    /durationMs must be an integer/,
  );
});

function cleanPayload(extra = {}) {
  return {
    kind: "payload_summary",
    action: "echo_run",
    outcome: "complete",
    samples: 2,
    not_attempted: 0,
    failure: null,
    counts: {
      attempted: 2,
      sent: 2,
      received: 2,
      lost: 0,
      duplicate: 0,
      mismatch: 0,
      late: 0,
      busy_dropped: 0,
      send_outcome_unknown: 0,
    },
    ...extra,
  };
}

test("raw RPC replies distinguish acknowledgement, refusal, and malformed outcome", () => {
  assert.equal(classifyActionResult("rpc", { ok: true, data: {} }), "acknowledged");
  assert.equal(classifyActionResult("rpc", { ok: false, error: "refused" }), "failed");
  assert.equal(classifyActionResult("rpc", { data: {} }), "outcome_unknown");
});

test("payload failure cannot pass and a nested ambiguous outcome dominates", () => {
  assert.equal(
    classifyActionResult("echo_run", cleanPayload({ outcome: "failed" })),
    "failed",
  );
  assert.equal(
    classifyActionResult(
      "echo_run",
      cleanPayload({ route_observations: { failure: { category: "transport_outcome_unknown" } } }),
    ),
    "outcome_unknown",
  );
  assert.equal(
    classifyActionResult("echo_run", cleanPayload({ workload_outcome: "outcome_unknown" })),
    "outcome_unknown",
  );
  assert.equal(
    classifyActionResult("echo_run", cleanPayload({ workload_outcome: "failed" })),
    "failed",
  );
});

test("Windows endpoint selection permits only explicit local trial pipes", () => {
  const home = "C:\\isolated-home";
  assert.equal(controlEndpoint(home, {}, "win32"), "\\\\.\\pipe\\myownmesh.sock");
  assert.equal(
    controlEndpoint(
      home,
      { daemon: { control_socket: "\\\\.\\pipe\\myownmesh-live-field-a" } },
      "win32",
    ),
    "\\\\.\\pipe\\myownmesh-live-field-a",
  );
  for (const control_socket of [
    "\\\\server\\pipe\\myownmesh-live-field-a",
    "\\\\?\\pipe\\myownmesh-live-field-a",
    "C:\\tmp\\myownmesh-live-field-a",
    "\\\\.\\pipe\\myownmesh.sock",
    "\\\\.\\pipe\\myownmesh-live-bad/name",
  ]) {
    assert.throws(
      () => controlEndpoint(home, { daemon: { control_socket } }, "win32"),
      /absolute local.*myownmesh-live-/,
    );
  }
});

test("endpoint preflight fails closed on Windows except exact absence", () => {
  assert.equal(endpointProbeDisposition("win32", { code: "ENOENT" }), "absent");
  for (const code of ["EACCES", "EBUSY", "ECONNREFUSED", "ETIMEDOUT", undefined]) {
    assert.equal(endpointProbeDisposition("win32", { code }), "refuse");
  }
  assert.equal(endpointProbeDisposition("linux", { code: "ENOENT" }), "absent");
  assert.equal(endpointProbeDisposition("linux", { code: "ECONNREFUSED" }), "absent");
  assert.equal(endpointProbeDisposition("linux", { code: "EACCES" }), "refuse");
});

function runningChild() {
  return { pid: 41, exitCode: null, signalCode: null };
}

test("owned child exits during the finite graceful phase", async () => {
  const signals = [];
  const waits = [];
  const result = await stopOwnedChild(runningChild(), 10_000, {
    platform: "linux",
    monoMs: () => 0,
    signalGroup: (pid, signal) => signals.push([pid, signal]),
    waitForExit: async (_child, timeoutMs) => {
      waits.push(timeoutMs);
      return { exitCode: 0, signal: null };
    },
  });
  assert.deepEqual(signals, [[41, "SIGINT"]]);
  assert.deepEqual(waits, [8_000]);
  assert.equal(result.mode, "graceful_sigint");
  assert.deepEqual(result.phase_budget, {
    total_ms: 10_000,
    graceful_ms: 8_000,
    forced_join_ms: 2_000,
  });
});

test("non-exiting grace reserves time for forced process-group exit observation", async () => {
  const signals = [];
  const waits = [];
  let now = 0;
  const result = await stopOwnedChild(runningChild(), 10_000, {
    platform: "linux",
    monoMs: () => now,
    signalGroup: (pid, signal) => signals.push([pid, signal]),
    waitForExit: async (_child, timeoutMs) => {
      waits.push(timeoutMs);
      now += timeoutMs;
      if (waits.length === 1) throw new ControllerError("grace expired");
      return { exitCode: null, signal: "SIGKILL" };
    },
  });
  assert.deepEqual(signals, [[41, "SIGINT"], [41, "SIGKILL"]]);
  assert.deepEqual(waits, [8_000, 2_000]);
  assert.equal(result.mode, "forced_sigkill");
  assert.equal(result.signalSent, true);
  assert.equal(result.signal, "SIGKILL");
});

test("unobserved forced exit remains a typed failure with phase evidence", async () => {
  const signals = [];
  let now = 0;
  await assert.rejects(
    stopOwnedChild(runningChild(), 10_000, {
      platform: "linux",
      monoMs: () => now,
      signalGroup: (pid, signal) => signals.push([pid, signal]),
      waitForExit: async (_child, timeoutMs) => {
        now += timeoutMs;
        throw new ControllerError("exit unobserved");
      },
    }),
    (error) => {
      assert.equal(error.result?.mode, "forced_sigkill_unconfirmed");
      assert.equal(error.result?.signalSent, true);
      assert.equal(error.result?.phase_budget?.forced_join_ms, 2_000);
      return true;
    },
  );
  assert.deepEqual(signals, [[41, "SIGINT"], [41, "SIGKILL"]]);
});

test("an expired shutdown deadline sends no signal and cannot claim exit", async () => {
  const signals = [];
  await assert.rejects(
    stopOwnedChild(runningChild(), 100, {
      platform: "linux",
      monoMs: () => 100,
      signalGroup: (pid, signal) => signals.push([pid, signal]),
      waitForExit: async () => assert.fail("expired deadline must not wait"),
    }),
    (error) => {
      assert.equal(error.code, "ETIMEDOUT");
      assert.equal(error.result?.mode, "shutdown_deadline_expired");
      assert.equal(error.result?.signalSent, false);
      return true;
    },
  );
  assert.deepEqual(signals, []);
});

test("listener registration is provisional and relay acceptance is not readiness", () => {
  assert.equal(classifyActionResult("echo_listen", { kind: "echo_ready" }), "ready");
  assert.equal(
    classifyActionResult("relay_echo_listen", { kind: "relay_accepting" }),
    "pending",
  );
});

test("fact mutation acknowledgement is explicitly not convergence", () => {
  assert.equal(
    classifyActionResult("role-stream", { status: "acknowledged_not_convergence" }),
    "acknowledged",
  );
  assert.notEqual(
    classifyActionResult("role-stream", { status: "acknowledged_not_convergence" }),
    "passed",
  );
});

test("only clean complete channel and closed-relay payload summaries pass", () => {
  assert.equal(classifyActionResult("echo_run", cleanPayload()), "passed");
  assert.equal(
    classifyActionResult(
      "relay_echo_run",
      cleanPayload({ action: "relay_echo_run", close_outcome: "closed" }),
    ),
    "passed",
  );
  assert.equal(
    classifyActionResult(
      "relay_echo_run",
      cleanPayload({ action: "relay_echo_run", close_outcome: "close_not_attempted_deadline" }),
    ),
    "failed",
  );
  assert.equal(
    classifyActionResult("echo_run", cleanPayload({ counts: { ...cleanPayload().counts, lost: 1 } })),
    "failed",
  );
});

test("listener lifetime terminal summary and cleanup determine final status", () => {
  assert.equal(classifyLifetimeResult("echo_listen", cleanPayload(), null, null), "passed");
  assert.equal(
    classifyLifetimeResult("echo_listen", cleanPayload({ outcome: "failed" }), null, null),
    "failed",
  );
  assert.equal(
    classifyLifetimeResult(
      "relay_echo_listen",
      cleanPayload({ action: "relay_echo_listen", close_outcome: "closed" }),
      new ControllerError("close outcome is unknown", "outcome_unknown"),
      null,
    ),
    "outcome_unknown",
  );
});

test("collection expiry without explicit stop is censored and non-successful", () => {
  const error = collectionDeadlineError(false, true);
  assert.equal(error?.kind, "censored");
  assert.equal(controllerStatus(error), "censored");
  assert.equal(collectionDeadlineError(true, true), null);
});

test("terminal capture and close failures propagate a nonzero controller outcome", async () => {
  const writeFailure = new Error("terminal write failed");
  const writer = new JsonlWriter({
    writeFile: async () => {
      throw writeFailure;
    },
    sync: async () => {},
    close: async () => {},
  });
  await assert.rejects(writer.append({ type: "controller_terminal" }), /terminal write failed/);
  await assert.rejects(writer.close(), /terminal write failed/);
  assert.equal(controllerStatus(mergeControllerError(null, writeFailure)), "failed");

  const closeFailure = new Error("terminal close failed");
  const closeWriter = new JsonlWriter({
    writeFile: async () => {},
    sync: async () => {},
    close: async () => {
      throw closeFailure;
    },
  });
  await closeWriter.append({ type: "controller_terminal" });
  await assert.rejects(closeWriter.close(), /terminal close failed/);
  assert.equal(controllerStatus(mergeControllerError(null, closeFailure)), "failed");
});

test("unknown terminal evidence dominates an earlier ordinary failure", () => {
  const composed = mergeControllerError(
    new ControllerError("ordinary failure"),
    new ControllerError("write may have happened", "outcome_unknown"),
  );
  assert.equal(controllerStatus(composed), "outcome_unknown");
});

function deferredTimingControl() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

function timingPipe() {
  const socket = new EventEmitter();
  const writes = [];
  const arrivals = [deferredTimingControl(), deferredTimingControl()];
  socket.write = (_encoded, callback) => {
    writes.push(callback);
    arrivals[writes.length - 1]?.resolve();
    return true;
  };
  socket.destroy = () => socket.emit("close");
  const connection = new JsonLineConnection(socket);
  const client = new RpcClient("unused-test-endpoint", monoMs() + 5_000);
  client.connection = connection;
  return { client, connection, socket, writes, arrivals,
    reply(value) { socket.emit("data", Buffer.from(`${JSON.stringify(value)}\n`)); } };
}

const RPC_TIMING_PHASES = ["enqueued", "dequeued", "connection_ready", "write_completion_observed", "reply_observed"];

test("per-call RPC timings isolate two queued calls and distinguish held write from held reply", { timeout: 5_000 }, async () => {
  const pipe = timingPipe(), a = [], b = [];
  const aWritten = deferredTimingControl();
  const first = pipe.client.rpc({ op: "first" }, 1_000, undefined, (phase, at) => {
    a.push([phase, at]); if (phase === "write_completion_observed") aWritten.resolve();
  });
  const second = pipe.client.rpc({ op: "second" }, 1_000, undefined, (phase, at) => b.push([phase, at]));
  try {
    await pipe.arrivals[0].promise;
    assert.deepEqual(a.map(row => row[0]), RPC_TIMING_PHASES.slice(0, 3));
    assert.deepEqual(b.map(row => row[0]), ["enqueued"]);
    pipe.writes[0](); await aWritten.promise;
    assert.deepEqual(a.map(row => row[0]), RPC_TIMING_PHASES.slice(0, 4));
    assert.deepEqual(b.map(row => row[0]), ["enqueued"]);
    const firstReply = { ok: true, data: { value: 1 } };
    pipe.reply(firstReply); assert.deepEqual(await first, firstReply);
    await pipe.arrivals[1].promise;
    assert.deepEqual(b.map(row => row[0]), RPC_TIMING_PHASES.slice(0, 3));
    pipe.writes[1](); pipe.reply({ ok: true, data: { value: 2 } });
    assert.equal((await second).data.value, 2);
    for (const rows of [a, b]) {
      assert.deepEqual(rows.map(row => row[0]), RPC_TIMING_PHASES);
      rows.forEach((row, i) => {
        assert.equal(row.length, 2); assert.ok(Number.isFinite(row[1]));
        if (i) assert.ok(row[1] >= rows[i - 1][1]);
      });
    }
    assert.ok(b[1][1] >= a[4][1]);
    assert.equal(first.timingObserverFailed, false); assert.equal(second.timingObserverFailed, false);
    assert.deepEqual(Object.getOwnPropertyNames(first), ["timingObserverFailed"]);
    assert.deepEqual(Object.keys(pipe.client).sort(), ["connection", "deadlineMs", "endpoint", "pending", "signal", "tail"]);
    assert.equal(pipe.client.pending, 0); assert.equal(pipe.connection.waiters.length, 0);
    assert.equal(pipe.connection.frames.length, 0);
  } finally { pipe.client.close(); }
});

test("RPC observer throws never discard a reply and disable only that call's notifications", { timeout: 5_000 }, async () => {
  for (const failAt of RPC_TIMING_PHASES) {
    const pipe = timingPipe(), phases = [];
    const call = pipe.client.rpc({ op: "opaque-request" }, 1_000, undefined, (...args) => {
      assert.equal(args.length, 2); assert.equal(typeof args[0], "string");
      assert.ok(Number.isFinite(args[1])); phases.push(args[0]);
      if (args[0] === failAt) throw new Error("not-exported-observer-error");
    });
    try {
      await pipe.arrivals[0].promise; pipe.writes[0]();
      pipe.reply({ ok: true, data: { opaqueReply: true } });
      assert.deepEqual(await call, { ok: true, data: { opaqueReply: true } });
      assert.deepEqual(phases, RPC_TIMING_PHASES.slice(0, RPC_TIMING_PHASES.indexOf(failAt) + 1));
      assert.equal(call.timingObserverFailed, true);
      assert.equal(Object.getOwnPropertyDescriptor(call, "timingObserverFailed").set, undefined);
      assert.equal(pipe.client.pending, 0);
      assert.equal(pipe.connection.frames.length, 0); assert.equal(pipe.connection.waiters.length, 0);
      const nextPhases = [];
      const next = pipe.client.rpc({ op: "next" }, 1_000, undefined, (phase) => nextPhases.push(phase));
      await pipe.arrivals[1].promise; pipe.writes[1](); pipe.reply({ ok: true });
      assert.deepEqual(await next, { ok: true });
      assert.deepEqual(nextPhases, RPC_TIMING_PHASES);
      assert.equal(next.timingObserverFailed, false);
    } finally { pipe.client.close(); }
  }
});

test("timed cancellation retains pre-write refusal versus post-write unknown and clears per-call custody", { timeout: 5_000 }, async () => {
  for (const afterWrite of [false, true]) {
    const pipe = timingPipe(), work = new AbortController(), phases = [];
    if (!afterWrite) work.abort();
    const call = pipe.client.rpc({ op: "cancel" }, 1_000, work.signal, (phase) => phases.push(phase));
    try {
      if (afterWrite) { await pipe.arrivals[0].promise; work.abort(); }
      await assert.rejects(call, error => error.kind === (afterWrite ? "outcome_unknown" : "failed"));
      assert.equal(pipe.writes.length, afterWrite ? 1 : 0);
      assert.deepEqual(phases, RPC_TIMING_PHASES.slice(0, 3));
      assert.equal(call.timingObserverFailed, false);
      assert.equal(pipe.client.pending, 0); assert.equal(pipe.client.connection, null);
      const count = phases.length;
      if (afterWrite) pipe.writes[0]();
      await Promise.resolve();
      assert.equal(phases.length, count, "late write completion cannot notify a settled observer");
    } finally { pipe.client.close(); }
  }
});

test("default RPC emits no diagnostic properties and observer failure does not mask transport failure", { timeout: 5_000 }, async () => {
  const pipe = timingPipe();
  const call = pipe.client.rpc({ op: "ordinary" }, 1_000);
  try {
    assert.equal(Object.hasOwn(call, "timingObserverFailed"), false);
    await pipe.arrivals[0].promise; pipe.writes[0](); pipe.reply({ ok: false, error: "ordinary-refusal" });
    assert.deepEqual(await call, { ok: false, error: "ordinary-refusal" });
    const work = new AbortController(); work.abort();
    const failed = pipe.client.rpc({ op: "cancel" }, 1_000, work.signal, () => { throw new Error("observer"); });
    await assert.rejects(failed, error => error.kind === "failed");
    assert.equal(failed.timingObserverFailed, true);
  } finally { pipe.client.close(); }
});

test("shared persistent and standalone RPC adapter preserves observer and cleanup signal positions", () => {
  for (const owner of ["PeerSession", "standalone"]) {
    const calls = [], work = new AbortController(); let cleanup = false;
    const client = { rpc(...args) { calls.push(args); return Promise.resolve({ ok: true }); } };
    const rpc = createRpcContextAdapter(client, work.signal, () => cleanup);
    const request = { op: owner }, observer = () => {};
    rpc(request, 123, observer); cleanup = true; rpc(request, 456, observer);
    assert.deepEqual(calls.map(args => args.length), [4, 4]);
    assert.equal(calls[0][0], request); assert.equal(calls[0][1], 123);
    assert.equal(calls[0][2], work.signal); assert.equal(calls[0][3], observer);
    assert.equal(calls[1][2], undefined); assert.equal(calls[1][3], observer);
    rpc(request, 789);
    assert.equal(calls[2].length, 3, "default adapter keeps its original argument shape");
  }
});

test("both production context sites use the tested synchronous RPC forwarding adapter", async () => {
  const source = await readFile(new URL("../live-device-peer.mjs", import.meta.url), "utf8");
  assert.ok(source.includes("rpc: createRpcContextAdapter(this.rpc, this.workAbort.signal, () => this.cleanupMode)"));
  assert.ok(source.includes("rpc: createRpcContextAdapter(rpc, workAbort.signal, () => cleanupMode)"));
  assert.equal(source.match(/rpc: createRpcContextAdapter\(/g)?.length, 2);
});

test("buffered reply timing is RPC observation after write completion, not parser arrival", { timeout: 5_000 }, async () => {
  const pipe = timingPipe(), phases = [];
  const call = pipe.client.rpc({ op: "buffered" }, 1_000, undefined, (phase) => phases.push(phase));
  try {
    await pipe.arrivals[0].promise;
    pipe.reply({ ok: true });
    assert.equal(pipe.connection.frames.length, 1);
    assert.deepEqual(phases, RPC_TIMING_PHASES.slice(0, 3));
    pipe.writes[0](); assert.deepEqual(await call, { ok: true });
    assert.deepEqual(phases, RPC_TIMING_PHASES);
  } finally { pipe.client.close(); }
});

const ROUTE_COMMAND = Object.freeze({ id: "trace", action: "route_trace_listen", network: "route-test",
  run_label: "first-echo-route-cc6-c1", samples: 16, expected_rows: 32, max_rows: 64 });

async function withRouteHub(control) {
  const root = await mkdtemp(path.join(os.tmpdir(), "myownmesh-route-events-"));
  const endpoint = process.platform === "win32"
    ? `\\\\.\\pipe\\${path.basename(root)}` : path.join(root, "events.sock");
  const work = new AbortController(), rpcCalls = [], subscriptions = [];
  let stream, barrier;
  const server = net.createServer(socket => {
    stream = socket; let input = "";
    socket.setEncoding("utf8");
    socket.on("data", chunk => {
      input += chunk;
      const newline = input.indexOf("\n");
      if (newline < 0) return;
      subscriptions.push(JSON.parse(input.slice(0, newline))); input = input.slice(newline + 1);
      socket.write(`${JSON.stringify({ ok: true, data: { client_id: "test-client", client_capability: "test-only" } })}\n`);
    });
  });
  await listen(server, endpoint);
  const hub = new EventHub(endpoint, { rpc: async request => { rpcCalls.push(request); return { ok: true }; } },
    monoMs() + 8_000, work.signal);
  // Existing channel dispatch supplies a deterministic fence after test frames.
  // No channel_subscribe RPC is made by the route lifetime or this test fence.
  hub.subscriptions.set("test-fence", { network: "test-fence", channel: "test-fence", onEvent: () => barrier?.resolve() });
  const pump = async frames => {
    barrier = deferredTimingControl();
    const fence = { kind: "channel_inbound", network: "test-fence", channel: "test-fence" };
    stream.write([...frames, fence].map(frame => JSON.stringify(frame) + "\n").join(""));
    await barrier.promise;
  };
  try { await control({ hub, work, pump, rpcCalls, subscriptions, get stream() { return stream; } }); }
  finally {
    work.abort(); await hub.close().catch(() => {});
    stream?.destroy(); await closeServer(server); await rm(root, { recursive: true, force: true });
  }
}

function routeEvent(detail, network = "route_flow_diagnostic") {
  return { kind: "event", event: { event_kind: "diag", network_id: network,
    category: "route_flow", ts: 0, level: "info", message: "never retain this raw message", detail } };
}

function routeRow(index, change = {}) {
  return { schema: "myownmesh.route-flow/v2", kind: "disposition", run_id: ROUTE_COMMAND.run_label,
    direction: index < 16 ? "request" : "reply", seq: index % 16,
    route_id: (index + 1).toString(16).padStart(32, "0"), role: "relay", hop_index: 2, remaining_ttl: 2,
    owner_epoch: "18446744073709551615", callback_to_insert_us: 0, insert_to_dequeue_us: 1,
    dequeue_to_handler_us: 2, handler_to_route_decision_us: 3, route_dispatch_us: 4, handler_total_us: 9,
    disposition_finished_mono_us: index, outcome: "delivered", ...change };
}

test("route v2 rejects v1 and missing or invalid process-local monotonic fields", { timeout: 10_000 }, async () => {
  const missing = routeRow(0);
  delete missing.disposition_finished_mono_us;
  const cases = [missing,
    routeRow(0, { schema: "myownmesh.route-flow/v1" }),
    { schema: "myownmesh.route-flow/v1", kind: "overflow", capacity: 64, outcome: "outcome_unknown" },
    ...[null, -1, 0.5, 86400000001, Number.MAX_SAFE_INTEGER + 1, "1"]
      .map(value => routeRow(0, { disposition_finished_mono_us: value }))];
  for (const row of cases) {
    await withRouteHub(async ({ hub, pump }) => {
      const lifetime = await hub.listenRouteTrace(ROUTE_COMMAND);
      await pump([routeEvent(row)]);
      const result = await lifetime.done;
      assert.equal(result.failure_code, "malformed_selected_diag");
      assert.equal(result.complete, false); assert.deepEqual(result.rows, []);
    });
  }
});

test("route v2 retains monotonic endpoints and maximal encoded row fits unchanged 640 byte slot", { timeout: 5_000 }, async () => {
  // Maximal accepted relay row: all bounded ASCII strings/numbers are at their
  // widest. Destination's longer role loses 12 bytes to required null dispatch;
  // origin also requires null ingress. No escaping expansion is possible here.
  const run_label = "Z".repeat(80);
  const maximal = routeRow(15, { run_id: run_label, hop_index: 255, remaining_ttl: 255,
    callback_to_insert_us: Number.MAX_SAFE_INTEGER, insert_to_dequeue_us: Number.MAX_SAFE_INTEGER,
    dequeue_to_handler_us: Number.MAX_SAFE_INTEGER, handler_to_route_decision_us: Number.MAX_SAFE_INTEGER,
    route_dispatch_us: Number.MAX_SAFE_INTEGER, handler_total_us: Number.MAX_SAFE_INTEGER,
    disposition_finished_mono_us: 86400000000, outcome: "outcome_unknown" });
  assert.equal(Buffer.byteLength(JSON.stringify(maximal), "utf8"), 628);
  assert.ok(Buffer.byteLength(JSON.stringify(maximal), "utf8") + 1 <= 640, "slot includes row separator");
  assert.equal(64 * 640 + 2048, 43008, "existing summary reserve unchanged");
  await withRouteHub(async ({ hub, pump }) => {
    const lifetime = await hub.listenRouteTrace({ ...ROUTE_COMMAND, run_label });
    const expected = Array.from({ length: 32 }, (_, index) => routeRow(index, {
      run_id: run_label, disposition_finished_mono_us: index === 0 ? 0 : 86400000000 }));
    await pump(expected.map(row => routeEvent(row)));
    await lifetime.cleanup();
    const result = await lifetime.done;
    assert.equal(result.complete, true); assert.deepEqual(result.rows, expected);
    assert.equal(result.rows[0].disposition_finished_mono_us, 0);
    assert.equal(result.rows[31].disposition_finished_mono_us, 86400000000);
  });
});

test("route actual EventHub collects exact 32 without extra RPC and joins only at cleanup", { timeout: 5_000 }, async () => {
  await withRouteHub(async ({ hub, pump, rpcCalls, subscriptions }) => {
    const lifetime = await hub.listenRouteTrace(ROUTE_COMMAND);
    let settled = false; lifetime.done.then(() => { settled = true; });
    await pump(Array.from({ length: 32 }, (_, index) => routeEvent(routeRow(index))));
    assert.equal(settled, false, "no early terminal when the expected count arrives");
    await lifetime.cleanup();
    const result = await lifetime.done;
    assert.equal(result.complete, true); assert.equal(result.failure_code, null);
    assert.equal(result.observed_rows, 32); assert.equal(result.rows.length, 32);
    assert.equal(result.network_attribution, "command_only_native_sentinel");
    assert.deepEqual(result.rows, Array.from({ length: 32 }, (_, index) => routeRow(index)));
    assert.equal(JSON.stringify(result).includes("never retain"), false);
    assert.equal(hub.routeTrace, null); assert.equal(rpcCalls.length, 0);
    assert.deepEqual(subscriptions, [{ op: "events_subscribe" }]);
    assert.equal(classifyLifetimeResult("route_trace_listen", result), "passed");
  });
});

test("route actual EventHub refuses malformed scalar growth, duplicate sets and bounded overflow", { timeout: 10_000 }, async () => {
  const cases = [
    [[routeEvent(routeRow(0)), routeEvent(routeRow(0))], "duplicate_route_role"],
    [[routeEvent(routeRow(0)), routeEvent(routeRow(0, { route_id: "f".repeat(32) }))], "duplicate_direction_seq"],
    [[routeEvent({ schema: "myownmesh.route-flow/v2", kind: "overflow", capacity: 64, outcome: "outcome_unknown" })], "overflow"],
    // With seq constrained to 0..15, a 65-row cohort necessarily fails before
    // the 65th insertion (duplicate or malformed), never silently truncates.
    [Array.from({ length: 65 }, (_, index) => routeEvent(routeRow(index % 32))), "duplicate_route_role"],
    ...[{ extra: "not-retained" }, { seq: 16 }, { direction: "other" }, { run_id: "dotted.run" },
      { owner_epoch: "18446744073709551616" }, { owner_epoch: 1 },
      { route_dispatch_us: Number.MAX_SAFE_INTEGER + 1 }, { handler_total_us: -1 },
      { role: "origin" }, { role: "destination" }, { route_id: "F".repeat(32) }]
      .map(change => [[routeEvent(routeRow(0, change))], "malformed_selected_diag"]),
  ];
  for (const [frames, code] of cases) {
    await withRouteHub(async ({ hub, pump }) => {
      const lifetime = await hub.listenRouteTrace(ROUTE_COMMAND);
      await pump(frames);
      const result = await lifetime.done;
      assert.equal(result.failure_code, code); assert.equal(result.complete, false);
      assert.ok(result.rows.length <= 32); assert.equal(hub.routeTrace, null);
      assert.equal(JSON.stringify(result).includes("not-retained"), false);
    });
  }
});

test("route different run is ignored and nondelivery cannot qualify an otherwise complete set", { timeout: 5_000 }, async () => {
  await withRouteHub(async ({ hub, pump }) => {
    const lifetime = await hub.listenRouteTrace(ROUTE_COMMAND);
    await pump([routeEvent(routeRow(0, { run_id: "different-run" })),
      ...Array.from({ length: 32 }, (_, index) => routeEvent(routeRow(index,
        index === 0 ? { outcome: "outcome_unknown" } : {})))]);
    await lifetime.cleanup();
    const result = await lifetime.done;
    assert.equal(result.observed_rows, 32); assert.equal(result.failure_code, "route_not_delivered");
    assert.equal(result.complete, false); assert.equal(result.outcome, "failed");
    assert.equal(result.rows[0].outcome, "outcome_unknown");
    assert.equal(classifyLifetimeResult("route_trace_listen", result), "failed");
    const unknown = new ControllerError("test cleanup uncertainty", "outcome_unknown");
    assert.equal(classifyLifetimeResult("route_trace_listen", result, unknown), "outcome_unknown");
    assert.equal(classifyLifetimeResult("route_trace_listen", result, null, unknown), "outcome_unknown");
  });
});

test("route native label grammar preserves hyphens and underscores in command and selected rows", { timeout: 5_000 }, async () => {
  await withRouteHub(async ({ hub, pump }) => {
    const run_label = "first-echo_route-cc6_c1";
    const lifetime = await hub.listenRouteTrace({ ...ROUTE_COMMAND, run_label });
    assert.equal(lifetime.result.run_label, run_label);
    await pump(Array.from({ length: 32 }, (_, index) => routeEvent(routeRow(index, { run_id: run_label }))));
    await lifetime.cleanup();
    const result = await lifetime.done;
    assert.equal(result.complete, true); assert.equal(result.observed_rows, 32);
    assert.equal(result.rows.every(row => row.run_id === run_label), true);
  });
});

test("route origin and destination preserve unavailable durations as null, not zero", { timeout: 5_000 }, async () => {
  await withRouteHub(async ({ hub, pump }) => {
    const lifetime = await hub.listenRouteTrace(ROUTE_COMMAND);
    const expected = Array.from({ length: 32 }, (_, index) => routeRow(index, index < 16
      ? { role: "origin", owner_epoch: null, callback_to_insert_us: null,
        insert_to_dequeue_us: null, dequeue_to_handler_us: null }
      : { role: "destination", route_dispatch_us: null }));
    await pump(expected.map(row => routeEvent(row)));
    await lifetime.cleanup();
    const result = await lifetime.done;
    assert.equal(result.complete, true); assert.deepEqual(result.rows, expected);
  });
});

test("route orderly finish cannot mask an already-recorded socket failure", { timeout: 5_000 }, async () => {
  await withRouteHub(async ({ hub, pump, work }) => {
    const lifetime = await hub.listenRouteTrace(ROUTE_COMMAND);
    await pump(Array.from({ length: 32 }, (_, index) => routeEvent(routeRow(index))));
    // Reproduce the narrow socket-terminal-before-pump-continuation window.
    // The next normal finish must latch the actual existing terminal error.
    const failure = new ControllerError("test retained socket failure");
    hub.connection.terminal = failure;
    hub.finishRouteTrace(); work.abort();
    assert.equal((await lifetime.done).failure_code, "stream_failure");
    await assert.rejects(hub.close(), error => error === failure);
  });
});

test("route normal PeerSession close quiesces actual EventHub before work abort and retains digest terminal", { timeout: 5_000 }, async () => {
  await withRouteHub(async ({ hub, pump }) => {
    const writer = memoryWriter();
    const { session, child } = createPeerSessionTestHarness({ writer, events: hub,
      rpc: async () => { throw new Error("route action must not call RPC"); } });
    // The production constructor uses this same session-owned work signal.
    hub.signal = session.workAbort.signal;
    try {
      const result = await session.execute(ROUTE_COMMAND);
      assert.equal(result.status, "ready");
      const start = writer.rows.find(row => row.type === "command_started");
      assert.match(start.command_sha256, /^[0-9a-f]{64}$/);
      await pump(Array.from({ length: 32 }, (_, index) => routeEvent(routeRow(index))));
      assert.equal(writer.rows.some(row => row.type === "lifetime_terminal"), false);
      child.exitCode = 0;
      const terminal = await session.close();
      assert.equal(terminal.status, "complete"); assert.equal(writer.closed, true);
      const lifetimes = writer.rows.filter(row => row.type === "lifetime_terminal");
      assert.equal(lifetimes.length, 1); assert.equal(lifetimes[0].status, "passed");
      assert.equal(lifetimes[0].result.complete, true); assert.equal(lifetimes[0].result.failure_code, null);
      assert.equal(hub.routeTrace, null); await hub.worker;
    } finally { child.exitCode = 0; await session.close().catch(() => {}); }
  });
});

test("route actual PeerSession cancellation remains failed even after all 32 observations", { timeout: 5_000 }, async () => {
  await withRouteHub(async ({ hub, pump }) => {
    const writer = memoryWriter();
    const { session, child } = createPeerSessionTestHarness({ writer, events: hub, rpc: async () => ({ ok: true }) });
    hub.signal = session.workAbort.signal;
    try {
      await session.execute(ROUTE_COMMAND);
      await pump(Array.from({ length: 32 }, (_, index) => routeEvent(routeRow(index))));
      session.workAbort.abort(); child.exitCode = 0;
      await assert.rejects(session.close());
      const terminal = writer.rows.find(row => row.type === "lifetime_terminal");
      assert.equal(terminal.status, "failed"); assert.equal(terminal.result.failure_code, "cancelled");
    } finally { child.exitCode = 0; await session.close().catch(() => {}); }
  });
});

test("route lifetime fails selected malformed schema and lag, preserving redacted terminal-only evidence", { timeout: 10_000 }, async () => {
  for (const [frame, code] of [
    [routeEvent({ schema: "unknown", sensitive_payload: "must-not-be-retained" }), "malformed_selected_diag"],
    [{ kind: "lagged", skipped: 1 }, "lagged"],
  ]) {
    await withRouteHub(async ({ hub, pump, rpcCalls, subscriptions }) => {
      const lifetime = await hub.listenRouteTrace(ROUTE_COMMAND);
      assert.equal(lifetime.result.kind, "route_trace_ready");
      await pump([frame]);
      const result = await lifetime.done;
      assert.equal(result.complete, false); assert.equal(result.failure_code, code);
      assert.equal(result.rows.length, 0); assert.equal(hub.routeTrace, null);
      assert.equal(JSON.stringify(result).includes("must-not-be-retained"), false);
      assert.equal(JSON.stringify(result).includes("never retain"), false);
      await lifetime.cleanup();
      assert.equal(subscriptions.length, 1); assert.deepEqual(subscriptions[0], { op: "events_subscribe" });
      assert.equal(rpcCalls.length, 0);
    });
  }
});

test("route wrong-network and unrelated diag are ignored, incomplete cleanup fails without affecting default channel dispatch", { timeout: 5_000 }, async () => {
  await withRouteHub(async ({ hub, pump }) => {
    const lifetime = await hub.listenRouteTrace(ROUTE_COMMAND);
    await pump([routeEvent({ schema: "wrong", secret: "not-retained" }, "other-network"),
      { kind: "event", event: { event_kind: "diag", category: "other", network_id: ROUTE_COMMAND.network } }]);
    let settled = false; lifetime.done.then(() => { settled = true; });
    await Promise.resolve(); assert.equal(settled, false);
    await lifetime.cleanup();
    const result = await lifetime.done;
    assert.equal(result.failure_code, "incomplete_rows"); assert.deepEqual(result.rows, []);
    await pump([{ kind: "lagged", skipped: 9 }]);
    assert.equal(hub.failure, null, "default lag handling remains unchanged after observer removal");
  });
});

test("route command caps reject before any stream or RPC and one lifetime cannot retry", { timeout: 5_000 }, async () => {
  await withRouteHub(async ({ hub, rpcCalls, subscriptions }) => {
    for (const change of [{ samples: 17 }, { expected_rows: 33 }, { max_rows: 65 },
      { run_label: "bad label" }, { run_label: "dotted.run" }, { extra: 1 }, { network: "x".repeat(129) }]) {
      await assert.rejects(hub.listenRouteTrace({ ...ROUTE_COMMAND, ...change }), /route trace command shape/);
    }
    assert.equal(subscriptions.length, 0); assert.equal(rpcCalls.length, 0);
    const lifetime = await hub.listenRouteTrace(ROUTE_COMMAND);
    await lifetime.cleanup();
    await assert.rejects(hub.listenRouteTrace(ROUTE_COMMAND), /already used/);
  });
});

test("route cancellation and stream close settle owned lifetime; genuine stream failure remains observable", { timeout: 10_000 }, async () => {
  await withRouteHub(async ({ hub, work }) => {
    const lifetime = await hub.listenRouteTrace(ROUTE_COMMAND);
    work.abort();
    assert.equal((await lifetime.done).failure_code, "cancelled");
    await lifetime.cleanup(); await hub.close();
    assert.equal(hub.routeTrace, null);
  });
  await withRouteHub(async ctx => {
    const lifetime = await ctx.hub.listenRouteTrace(ROUTE_COMMAND);
    ctx.stream.destroy();
    assert.equal((await lifetime.done).failure_code, "stream_failure");
    await assert.rejects(ctx.hub.close(), /control connection closed/);
    assert.equal(ctx.hub.routeTrace, null);
  });
});
