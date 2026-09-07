// Mocked public IPC mechanics only. These controls are not live field evidence,
// a native provider test, or retrospective qualification of the refused 8KiB run.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { runPayload } from '../live-device-payload.mjs';

const PEER = 'b'.repeat(51) + 'a';
const PRESSURE = 'application gateway resource pressure: Pressure(ResourcePressure { scope_id: ResourceScopeId(17), authority: Admitted, dimension: OpaqueDependencyResidual, requested: 8380, in_use: 47, capacity: 8192 })';
const command = overrides => ({ action: 'echo_run', network: 'evidence-network',
  channel: 'evidence-channel', peer: PEER, run_id: 'evidence_only', samples: 3,
  bytes: 1024, timeout_ms: 1000, lifetime_ms: 5000, ...overrides });
const ok = data => ({ ok: true, data });

function fixture({ peers = [], reply = ok({ sent: true }), thrown = null } = {}) {
  const sends = [], emitted = [];
  let listener = null;
  let releases = 0;
  const ctx = {
    signal: new AbortController().signal,
    deadlineMs: performance.now() + 10_000,
    monoMs: () => performance.now(),
    emit: async record => { emitted.push(record); },
    subscribe: async (_network, _channel, receive) => {
      assert.equal(listener, null);
      listener = receive;
      return async () => { releases += 1; listener = null; };
    },
    rpc: async request => {
      if (request.op === 'peers_list') return ok({ peers });
      assert.equal(request.op, 'channel_send_to');
      sends.push(request);
      if (thrown) throw thrown;
      if (reply.ok === true) {
        queueMicrotask(() => listener?.({ kind: 'channel_inbound', network: request.network,
          channel: request.channel, from: PEER, payload: { ...request.payload, kind: 'echo' } }));
      }
      return reply;
    },
  };
  return { ctx, sends, emitted, releases: () => releases,
    receive: event => { assert(listener); listener(event); } };
}

function assertOneUnknown(result, f) {
  assert.equal(f.sends.length, 1);
  assert.equal(f.releases(), 1);
  assert.equal(result.outcome, 'send_outcome_unknown');
  assert.equal(result.counts.attempted, 1);
  assert.equal(result.counts.sent, 0);
  assert.equal(result.counts.received, 0);
  assert.equal(result.counts.send_outcome_unknown, 1);
  assert.equal(result.not_attempted, 2);
  assert.deepEqual(result.rtt_observations, []);
}

test('payload evidence accepts all actual tagged recovery tiers without claiming path proof', async () => {
  const tiers = ['steady', 'wake_probe', 'ice_watchdog', 'ice_restart', 'stop_start'];
  const peers = tiers.map(kind => ({ device_id: PEER, status: 'active', tier: { kind },
    authenticated: true, selected_pair: { private_marker: 'do-not-retain-pair' },
    label: 'do-not-retain-label', verification_code_received: 'do-not-retain-code',
    capabilities: { private_marker: 'do-not-retain-capabilities' } }));
  const f = fixture({ peers });
  const result = await runPayload(f.ctx, command({ samples: 1 }));
  assert.equal(result.outcome, 'complete');
  assert.equal(result.counts.received, 1);
  for (const snapshot of Object.values(result.route_observations)) {
    assert.equal(snapshot.available, true);
    assert.equal(snapshot.truncated, false);
    assert.equal(snapshot.total_rows, 5);
    assert.equal(snapshot.physical_hop_proof, false);
    assert.equal(snapshot.nomination_available, false);
    assert.deepEqual(snapshot.peers.map(row => row.tier), tiers.map(kind => ({ kind })));
    assert(snapshot.peers.every(row => row.selected_pair_present && row.authenticated));
    assert(!JSON.stringify(snapshot).includes('do-not-retain'));
  }
});

test('payload evidence rejects malformed tier schemas and keeps the 64-row observation bound', async () => {
  for (const tier of ['steady', null, [], { kind: 'invented' }, { kind: 'steady', extra: 'secret' }]) {
    const f = fixture({ peers: [{ device_id: PEER, status: 'active', tier, authenticated: true }] });
    const result = await runPayload(f.ctx, command({ samples: 1 }));
    for (const snapshot of Object.values(result.route_observations)) {
      assert.equal(snapshot.available, false);
      assert.equal(snapshot.failure.category, 'unsupported_peer_shape');
      assert.equal(snapshot.physical_hop_proof, false);
    }
  }
  const row = { device_id: PEER, status: 'active', tier: { kind: 'steady' }, authenticated: true };
  const f = fixture({ peers: Array.from({ length: 65 }, () => row) });
  const result = await runPayload(f.ctx, command({ samples: 1 }));
  for (const snapshot of Object.values(result.route_observations)) {
    assert.equal(snapshot.peers.length, 64);
    assert.equal(snapshot.total_rows, 65);
    assert.equal(snapshot.truncated, true);
    assert.equal(snapshot.physical_hop_proof, false);
  }
});

test('payload evidence retains exact Debug pressure fields but never retries or upgrades ok:false', async () => {
  const f = fixture({ reply: { ok: false, error: PRESSURE } });
  const result = await runPayload(f.ctx, command());
  assertOneUnknown(result, f);
  assert.equal(result.failure.stage, 'channel_send');
  assert.equal(result.failure.category, 'daemon_reported_failure');
  assert.deepEqual(result.failure.daemon_diagnostic, { kind: 'resource_pressure', scope_id: 17,
    authority: 'Admitted', dimension: 'OpaqueDependencyResidual', requested: 8380,
    in_use: 47, capacity: 8192 });
});

test('payload evidence retains only fixed known refusal strings and still stops on the first send', async () => {
  for (const error of ['network has been torn down', 'transport: data channel not open',
    'transport: peer send timed out']) {
    const f = fixture({ reply: { ok: false, error } });
    const result = await runPayload(f.ctx, command());
    assertOneUnknown(result, f);
    assert.deepEqual(result.failure.daemon_diagnostic, { kind: 'known_refusal', message: error });
  }
});

test('payload evidence redacts arbitrary secrets, appended text, oversized and unsafe numeric diagnostics', async () => {
  const errors = ['handle=private-handle capability=private-capability password=private-password',
    `${PRESSURE} secret=private-secret`, `${PRESSURE}\n`, 'é'.repeat(600),
    PRESSURE.replace('8380', '9007199254740993'),
    PRESSURE.replace('OpaqueDependencyResidual', 'SecretDimension'),
    PRESSURE.replace('Admitted', 'UnknownAuthority')];
  for (const error of errors) {
    const f = fixture({ reply: { ok: false, error, capability: 'ignored-reply-capability' } });
    const result = await runPayload(f.ctx, command());
    assertOneUnknown(result, f);
    assert.deepEqual(result.failure.daemon_diagnostic, { kind: 'redacted_error',
      utf8_bytes: Buffer.byteLength(error, 'utf8'),
      sha256: createHash('sha256').update(error).digest('hex') });
    const evidence = JSON.stringify([result, ...f.emitted]);
    assert(!evidence.includes('private-'));
    assert(!evidence.includes('ignored-reply-capability'));
    assert(!evidence.includes(error));
  }
  const f = fixture({ reply: { ok: false, error: { secret: 'not-a-string-secret' } } });
  const result = await runPayload(f.ctx, command());
  assertOneUnknown(result, f);
  assert.deepEqual(result.failure.daemon_diagnostic, { kind: 'redacted_nonstring_error' });
  assert(!JSON.stringify(result).includes('not-a-string-secret'));
});

test('payload evidence keeps transport failure unknown without serializing thrown secrets', async () => {
  const f = fixture({ thrown: new Error('timeout handle=private-handle capability=private-capability') });
  const result = await runPayload(f.ctx, command());
  assertOneUnknown(result, f);
  assert.equal(result.failure.category, 'transport_outcome_unknown');
  assert.equal(result.failure.daemon_diagnostic, undefined);
  assert(!JSON.stringify([result, ...f.emitted]).includes('private-'));
});

test('payload evidence measures body versus actual attempted packet and request JSON bytes', async () => {
  for (const bytes of [1024, 8192]) {
    // A refused mock is deliberate: do not turn a byte-count control into an
    // assertion that an actual provider admits this workload.
    const f = fixture({ reply: { ok: false, error: PRESSURE } });
    const result = await runPayload(f.ctx, command({ bytes }));
    assertOneUnknown(result, f);
    const request = f.sends[0];
    const size = result.last_send_encoding;
    assert.equal(result.body_bytes_per_sample, bytes);
    assert.equal(Buffer.byteLength(request.payload.body, 'utf8'), bytes);
    assert.equal(size.operation, 'channel_send_to');
    assert.equal(size.packet_json_bytes, Buffer.byteLength(JSON.stringify(request.payload), 'utf8'));
    assert.equal(size.request_json_bytes, Buffer.byteLength(JSON.stringify(request), 'utf8'));
    assert(size.packet_json_bytes > bytes);
    assert(size.request_json_bytes > size.packet_json_bytes);
    assert.match(size.scope, /not_native_wire_or_resource_claim/);
    if (bytes === 8192) assert(size.packet_json_bytes > 8192);
    else assert(size.packet_json_bytes + 4 < 8192); // Lower bound, not free capacity.
    assert.equal(result.verified_body_bytes, 0);
  }
});

test('payload responder preserves pressure diagnostics through its owned terminal summary', async () => {
  const f = fixture({ reply: { ok: false, error: PRESSURE } });
  const c = command({ action: 'echo_listen' });
  const lifetime = await runPayload(f.ctx, c);
  try {
    f.receive({ kind: 'channel_inbound', network: c.network, channel: c.channel, from: PEER,
      payload: { protocol: 'myownmesh.live-payload.v1', network: c.network, channel: c.channel,
        kind: 'request', run_id: c.run_id, seq: 0, body: '0123456789abcdef'.repeat(64) } });
    const result = await lifetime.done;
    assert.equal(result.outcome, 'echo_send_outcome_unknown');
    assert.equal(result.counts.received, 1);
    assert.equal(result.counts.sent, 0);
    assert.equal(result.counts.send_outcome_unknown, 1);
    assert.equal(result.failure.daemon_diagnostic.requested, 8380);
    assert.equal(f.sends.length, 1);
    assert.equal(f.releases(), 1);
  } finally { await lifetime.cleanup(); }
  assert.equal(f.releases(), 1);
});

test('diagnostic flag is strict, generic-echo-only and invalid preflight has no IPC effects', async () => {
  for (const diagnostic_timing of [null, 0, 1, 'true', {}, []]) {
    const f = fixture();
    f.ctx.rpc = f.ctx.subscribe = async () => assert.fail('invalid timing flag reached IPC');
    await assert.rejects(runPayload(f.ctx, command({ diagnostic_timing })),
      error => error.stage === 'preflight' && error.category === 'invalid_diagnostic_timing');
    assert.equal(f.sends.length, 0);
    assert.equal(f.releases(), 0);
    assert.equal(f.emitted.length, 0);
  }
  for (const action of ['relay_echo_run', 'relay_echo_listen']) {
    for (const diagnostic_timing of [false, true]) {
      const f = fixture();
      f.ctx.rpc = f.ctx.subscribe = async () => assert.fail('relay diagnostic preflight reached IPC');
      await assert.rejects(runPayload(f.ctx, command({ action, diagnostic_timing })),
        error => error.category === 'invalid_diagnostic_timing');
      assert.equal(f.sends.length, 0);
    }
  }
});

test('diagnostics leave default summary, packets, order and counters unchanged and serialize only terminal numeric evidence', async () => {
  const runs = [];
  for (const flag of [undefined, false, true]) {
    const f = fixture();
    const c = command(flag === undefined ? {} : { diagnostic_timing: flag });
    let emittedWhileOwned = false;
    f.ctx.emit = async () => { if (f.releases() === 0) emittedWhileOwned = true; };
    const result = await runPayload(f.ctx, c);
    runs.push({ result, sends: f.sends });
    assert.equal(emittedWhileOwned, false);
    if (flag !== true) assert.equal(Object.hasOwn(result, 'diagnostic_timing'), false);
    else {
      const e = result.diagnostic_timing;
      assert.equal(e.role, 'sender');
      assert.equal(e.rows.length, c.samples);
      for (const row of e.rows) {
        assert.equal(row.length, e.columns.length);
        assert(row.every(value => value === null || (Number.isFinite(value) && value >= 0)));
        assert(Buffer.byteLength(JSON.stringify(row)) <= e.row_json_bytes_bound);
      }
      assert.equal(e.rows_json_bytes, Buffer.byteLength(JSON.stringify(e.rows)));
      assert(Buffer.byteLength(JSON.stringify(e)) <= e.evidence_json_bytes_bound);
      assert(!JSON.stringify(e).includes(f.sends[0].payload.body));
      assert(!JSON.stringify(e).includes(PEER));
    }
  }
  assert.deepEqual(runs[0].sends, runs[1].sends);
  assert.deepEqual(runs[0].sends, runs[2].sends);
  assert.deepEqual(runs[0].result.counts, runs[2].result.counts);
  assert.deepEqual(Object.keys(runs[0].result), Object.keys(runs[1].result));
});

test('invalid and duplicate inbound evidence cannot allocate or overwrite a valid sender timing row', async () => {
  const f = fixture();
  let now = 100;
  f.ctx.monoMs = () => now;
  f.ctx.deadlineMs = 5000;
  f.ctx.rpc = async request => {
    if (request.op === 'peers_list') return ok({ peers: [] });
    const event = { kind: 'channel_inbound', network: request.network,
      channel: request.channel, from: PEER, payload: { ...request.payload, kind: 'echo' } };
    for (const invalid of [
      { ...event, from: 'c'.repeat(51) + 'a' },
      { ...event, network: 'wrong' }, { ...event, channel: 'wrong' },
      ...[{ run_id: 'wrong' }, { seq: 1 }, { body: 'secret' }].map(change =>
        ({ ...event, payload: { ...event.payload, ...change } })),
    ]) { now += 1; f.receive(invalid); }
    now = 120; f.receive(event);
    now = 150; f.receive(event);
    return ok({ sent: true });
  };
  const result = await runPayload(f.ctx, command({ samples: 1, diagnostic_timing: true }));
  assert.equal(result.counts.mismatch, 6);
  assert.equal(result.counts.duplicate, 1);
  assert.equal(result.counts.received, 1);
  const e = result.diagnostic_timing;
  assert.equal(e.rows.length, 1);
  assert.equal(e.rows[0][e.columns.indexOf('echo_validated')], 20);
  assert.equal(result.rtt_observations[0].rtt_ms, 20);
  assert(!JSON.stringify(e).includes('secret'));
});

test('diagnostics honor the existing maximum sample bound and explicit terminal evidence byte budget', async () => {
  const f = fixture();
  // Synchronous mocked echo/ACK progress, no network and no real-time waiting.
  f.ctx.monoMs = () => 100;
  f.ctx.deadlineMs = 10000;
  f.ctx.emit = async () => {};
  const result = await runPayload(f.ctx, command({ samples: 10_000, bytes: 1, diagnostic_timing: true }));
  const e = result.diagnostic_timing;
  assert.equal(result.counts.received, 10_000);
  assert.equal(e.rows.length, 10_000);
  assert.equal(e.row_limit, 10_000);
  assert.equal(e.evidence_json_bytes_bound, 5_132_050);
  assert(Buffer.byteLength(JSON.stringify(e)) <= e.evidence_json_bytes_bound);
  assert.deepEqual(e.rows.map(row => row[0]), Array.from({ length: 10_000 }, (_, i) => i));
  const refused = fixture();
  refused.ctx.rpc = refused.ctx.subscribe = async () => assert.fail('sample bound refusal reached IPC');
  await assert.rejects(runPayload(refused.ctx, command({ samples: 10_001, bytes: 1,
    diagnostic_timing: true })), error => error.category === 'invalid_samples');
  assert.equal(refused.sends.length, 0);
});

test('per-call RPC phases partition local waits with honest observation labels and no measured-path emit', async () => {
  const f = fixture();
  let now = 100, retainedObserver, emitted = false;
  f.ctx.monoMs = () => now;
  f.ctx.deadlineMs = 5000;
  f.ctx.emit = async () => { assert.equal(f.releases(), 1); emitted = true; };
  f.ctx.rpc = (request, _timeout, observe) => {
    if (request.op === 'peers_list') {
      assert.equal(observe, undefined, 'no general-purpose RPC tracing');
      return Promise.resolve(ok({ peers: [] }));
    }
    assert.equal(typeof observe, 'function');
    retainedObserver = observe;
    for (const [phase, at] of [['enqueued', 110], ['dequeued', 130], ['connection_ready', 140],
      ['write_completion_observed', 150], ['reply_observed', 170]]) {
      now = at; observe(phase, now);
      assert.equal(emitted, false);
    }
    now = 190;
    f.receive({ kind: 'channel_inbound', network: request.network, channel: request.channel,
      from: PEER, payload: { ...request.payload, kind: 'echo' } });
    now = 200;
    const promise = Promise.resolve(ok({ sent: true }));
    Object.defineProperty(promise, 'timingObserverFailed', { get: () => false });
    return promise;
  };
  const result = await runPayload(f.ctx, command({ samples: 1, diagnostic_timing: true }));
  const e = result.diagnostic_timing;
  const value = name => e.rows[0][e.columns.indexOf(name)];
  assert.equal(result.outcome, 'complete');
  assert.equal(result.rtt_observations[0].rtt_ms, 90);
  assert.equal(value('rpc_call_begin'), 0);
  assert.equal(value('rpc_enqueue'), 10);
  assert.equal(value('rpc_dequeue') - value('rpc_enqueue'), 20);
  assert.equal(value('rpc_connection_ready') - value('rpc_dequeue'), 10);
  assert.equal(value('rpc_write_completion_observed') - value('rpc_connection_ready'), 10);
  assert.equal(value('rpc_reply_observed') - value('rpc_write_completion_observed'), 20);
  assert.equal(value('send_ack'), 100);
  assert.equal(value('echo_validated'), 90);
  assert.equal(value('rpc_observer_failed'), 0);
  assert.equal(e.rpc_phase_breakdown_complete, true);
  assert.match(e.rpc_scope, /not_callback_or_parse_instants/);
  const terminal = JSON.stringify(e);
  retainedObserver('reply_observed', 999);
  retainedObserver('secret-capability-text', 999);
  assert.equal(JSON.stringify(e), terminal, 'terminal callback cannot mutate retained evidence');
});

test('failed, missing, malformed or out-of-order RPC timing never qualifies a complete phase breakdown', async () => {
  for (const mode of ['failed', 'unavailable', 'missing_phase', 'out_of_order', 'malformed', 'getter_throws']) {
    const f = fixture();
    let now = 100;
    f.ctx.monoMs = () => now;
    f.ctx.deadlineMs = 5000;
    f.ctx.rpc = (request, _timeout, observe) => {
      if (request.op === 'peers_list') return Promise.resolve(ok({ peers: [] }));
      const phases = ['enqueued', 'dequeued', 'connection_ready', 'write_completion_observed', 'reply_observed'];
      phases.forEach((phase, i) => {
        if (mode === 'missing_phase' && phase === 'dequeued') return;
        observe(phase, mode === 'out_of_order' && phase === 'dequeued' ? 105 : 110 + i * 10);
      });
      if (mode === 'malformed') {
        // No coercion or copying of peer/controller supplied data into evidence.
        observe('secret-capability', 100);
        observe('enqueued', { toString() { throw new Error('private'); } });
        observe('dequeued', NaN);
        observe('connection_ready', Infinity);
      }
      now = 160;
      f.receive({ kind: 'channel_inbound', network: request.network, channel: request.channel,
        from: PEER, payload: { ...request.payload, kind: 'echo' } });
      const promise = Promise.resolve(ok({ sent: true }));
      if (mode !== 'unavailable') Object.defineProperty(promise, 'timingObserverFailed', {
        get: () => {
          if (mode === 'getter_throws') throw new Error('private');
          return mode === 'failed';
        },
      });
      return promise;
    };
    const result = await runPayload(f.ctx, command({ samples: 1, diagnostic_timing: true }));
    assert.equal(result.outcome, 'complete', 'diagnostic incompleteness is not a fabricated send failure');
    assert.equal(result.counts.received, 1);
    const e = result.diagnostic_timing;
    assert.equal(e.rpc_phase_breakdown_complete, false, mode);
    const flag = e.rows[0][e.columns.indexOf('rpc_observer_failed')];
    assert.equal(flag, mode === 'unavailable' ? null
      : ['failed', 'missing_phase', 'malformed', 'getter_throws'].includes(mode) ? 1 : 0);
    assert(!JSON.stringify(e).includes('secret'));
    assert(!JSON.stringify(e).includes('private'));
  }
});

for (const order of ['ordered', 'swapped', 'duplicate']) {
  test(`RPC timing requires callback order even at equal timestamps: ${order}`, async () => {
    const f = fixture();
    let now = 100, sends = 0;
    f.ctx.monoMs = () => now;
    f.ctx.deadlineMs = 5000;
    f.ctx.rpc = (request, _timeout, observe) => {
      if (request.op === 'peers_list') return Promise.resolve(ok({ peers: [] }));
      sends += 1;
      const phases = ['enqueued', 'dequeued', 'connection_ready',
        'write_completion_observed', 'reply_observed'];
      if (order === 'swapped') [phases[0], phases[1]] = [phases[1], phases[0]];
      if (order === 'duplicate') phases.splice(1, 0, 'enqueued');
      now += 10;
      for (const phase of phases) observe(phase, now);
      now += 50;
      f.receive({ kind: 'channel_inbound', network: request.network, channel: request.channel,
        from: PEER, payload: { ...request.payload, kind: 'echo' } });
      const promise = Promise.resolve(ok({ sent: true }));
      Object.defineProperty(promise, 'timingObserverFailed', { get: () => false });
      return promise;
    };
    const result = await runPayload(f.ctx, command({ samples: 2, diagnostic_timing: true }));
    assert.equal(result.outcome, 'complete');
    assert.equal(sends, 2, 'diagnostic failure neither retries nor suppresses the next sample');
    assert.equal(result.counts.sent, 2);
    assert.equal(result.counts.received, 2);
    assert.equal(result.counts.lost, 0);
    assert.equal(result.counts.send_outcome_unknown, 0);
    assert.deepEqual(result.rtt_observations.map(row => row.rtt_ms), [60, 60]);
    const e = result.diagnostic_timing;
    assert.equal(e.rpc_phase_breakdown_complete, order === 'ordered');
    assert.equal(e.rows.length, 2, 'phase order is tracked independently for each call');
    for (const row of e.rows) {
      assert.equal(row[e.columns.indexOf('rpc_observer_failed')], order === 'ordered' ? 0 : 1);
      const times = ['rpc_enqueue', 'rpc_dequeue', 'rpc_connection_ready',
        'rpc_write_completion_observed', 'rpc_reply_observed'].map(name => row[e.columns.indexOf(name)]);
      assert(times.every(time => time === 10 + row[0] * 60),
        'timestamps alone are identical for all three callback-order cases');
    }
  });
}

test('RPC observation failure flag is retained on unknown write while default calls have no observer', async () => {
  for (const diagnostic_timing of [false, true]) {
    const f = fixture();
    let sends = 0;
    f.ctx.monoMs = () => 100;
    f.ctx.deadlineMs = 5000;
    f.ctx.rpc = function(request, _timeout, observe) {
      if (request.op === 'peers_list') return Promise.resolve(ok({ peers: [] }));
      sends += 1;
      assert.equal(arguments.length, diagnostic_timing ? 3 : 2);
      if (observe) observe('enqueued', 100);
      const promise = Promise.reject(new Error('private failed-write detail'));
      if (observe) Object.defineProperty(promise, 'timingObserverFailed', { get: () => true });
      return promise;
    };
    const result = await runPayload(f.ctx, command({ diagnostic_timing }));
    assert.equal(sends, 1);
    assert.equal(result.outcome, 'send_outcome_unknown');
    assert.equal(result.counts.sent, 0);
    if (diagnostic_timing) {
      const e = result.diagnostic_timing;
      assert.equal(e.rpc_phase_breakdown_complete, false);
      assert.equal(e.rows[0][e.columns.indexOf('rpc_observer_failed')], 1);
      assert.equal(e.rows[0][e.columns.indexOf('send_ack')], null);
      assert.equal(e.rows[0][e.columns.indexOf('send_outcome_unknown')], 0);
      assert(!JSON.stringify(e).includes('private'));
    } else assert.equal(Object.hasOwn(result, 'diagnostic_timing'), false);
  }
});
