import assert from "node:assert/strict";
import test from "node:test";

import {
  ControllerError,
  JsonlWriter,
  classifyActionResult,
  classifyLifetimeResult,
  collectionDeadlineError,
  controlEndpoint,
  controllerStatus,
  endpointProbeDisposition,
  mergeControllerError,
  stopOwnedChild,
} from "../live-device-peer.mjs";

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
