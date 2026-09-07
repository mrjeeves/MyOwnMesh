import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  ControllerError,
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
