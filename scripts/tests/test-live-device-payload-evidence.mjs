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
