// Controller mechanics only: mocked IPC is never live-network evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { runFacts } from '../live-device-facts.mjs';
import { runPayload } from '../live-device-payload.mjs';

const key = char => char.repeat(51) + 'a';
const A = key('a'), B = key('b'), D = key('c'), R = key('r');
const contextId = key('e');
const identity = (count = 0) => ({ context_id: contextId,
  admitted_fact_count: count, unresolved_fact_count: 0,
  projection_commitment: Array(32).fill(count), state_commitment: Array(32).fill(count) });
const ok = data => ({ ok: true, data });
function context(rpc) {
  return { rpc, requireOk(reply) { assert.equal(reply.ok, true); return reply.data; },
    monoMs: () => performance.now(), deadlineMs: performance.now() + 5000,
    signal: new AbortController().signal, emit: async () => {},
    subscribe: async () => async () => {} };
}
const payload = (action, peer, overrides = {}) => ({ action, peer,
  network: 'test', channel: 'perf', run_id: 'mock_only', samples: 4, bytes: 1024,
  timeout_ms: 1000, lifetime_ms: 3000, ...overrides });

test('channel responder and sender verify exact echoes and release subscriptions', async () => {
  const listeners = new Map();
  const make = (self, peer) => {
    const ctx = context(async request => {
      if (request.op === 'peers_list') return ok({ peers: [] });
      assert.equal(request.op, 'channel_send_to');
      assert.equal(request.peer, peer);
      queueMicrotask(() => listeners.get(peer)?.({ kind: 'channel_inbound',
        network: request.network, channel: request.channel, from: self, payload: request.payload }));
      return ok({ sent: true });
    });
    ctx.subscribe = async (_network, _channel, listener) => {
      listeners.set(self, listener);
      return async () => { listeners.delete(self); };
    };
    return ctx;
  };
  const listener = await runPayload(make(B, A), payload('echo_listen', A));
  try {
    const result = await runPayload(make(A, B), payload('echo_run', B));
    assert.equal(result.outcome, 'complete');
    assert.equal(result.counts.received, 4);
    assert.equal(result.verified_body_bytes, 4096);
    assert.equal(result.counts.lost, 0);
    assert.equal(result.rtt_observations.length, 4);
    assert(result.rtt_observations.every(row => row.rtt_ms >= 0));
    assert.equal((await listener.done).outcome, 'complete');
  } finally { await listener.cleanup(); }
  assert.equal(listeners.size, 0);
});

test('wrong-origin echo does not count as delivery', async () => {
  let receive;
  const ctx = context(async request => {
    if (request.op === 'peers_list') return ok({ peers: [] });
    queueMicrotask(() => receive({ kind: 'channel_inbound', network: 'test',
      channel: 'perf', from: D, payload: { ...request.payload, kind: 'echo' } }));
    return ok({ sent: true });
  });
  ctx.subscribe = async (_n, _c, fn) => { receive = fn; return async () => {}; };
  const result = await runPayload(ctx, payload('echo_run', B, { samples: 1, timeout_ms: 20 }));
  assert.equal(result.outcome, 'completed_with_unverified_samples');
  assert.equal(result.counts.received, 0);
  assert.equal(result.counts.lost, 1);
  assert.equal(result.counts.mismatch, 1);
});

test('unknown channel write is never retried', async () => {
  let writes = 0;
  const ctx = context(async request => {
    if (request.op === 'peers_list') return ok({ peers: [] });
    writes += 1; throw new Error('simulated connection loss');
  });
  const result = await runPayload(ctx, payload('echo_run', B));
  assert.equal(writes, 1);
  assert.equal(result.outcome, 'send_outcome_unknown');
  assert.equal(result.counts.send_outcome_unknown, 1);
});

test('opaque relay controller carries full 1024-byte bodies and closes both owners', async () => {
  const queues = { a: [], b: [] }, waiters = new Map(), closed = [];
  let maximumFrame = 0;
  const make = (self, peer, destination) => context(async request => {
    const tag = self === A ? 'a' : 'b';
    const owner = { handle: tag, generation: 1, allocation_epoch: 1 };
    const answer = (variant, data) => ok({ closed_relay: { [variant]: data } });
    if (request.op === 'peers_list') return ok({ peers: [] });
    if (request.op === 'closed_relay_open' || request.op === 'closed_relay_accept') {
      return answer(request.op.endsWith('open') ? 'opened' : 'accepted', {
        ...owner, network: 'test', peer, relay: R, session_id: Array(16).fill(1), max_frame_bytes: 16174 });
    }
    assert.equal(request.handle, tag);
    if (request.op === 'closed_relay_send') {
      maximumFrame = Math.max(maximumFrame, request.payload.length);
      if (waiters.has(destination)) {
        const resolve = waiters.get(destination); waiters.delete(destination); resolve(request.payload);
      } else queues[destination].push(request.payload);
      return answer('sent', { ...owner, bytes: request.payload.length });
    }
    if (request.op === 'closed_relay_recv') {
      const bytes = queues[tag].length ? queues[tag].shift() : await new Promise(resolve => waiters.set(tag, resolve));
      return answer('received', { ...owner, payload: bytes });
    }
    assert.equal(request.op, 'closed_relay_close');
    closed.push(tag); return answer('closed', owner);
  });
  const listener = await runPayload(make(B, A, 'a'), payload('relay_echo_listen', A, { relay: R }));
  const result = await runPayload(make(A, B, 'b'), payload('relay_echo_run', B, { relay: R }));
  assert.equal(result.outcome, 'complete');
  assert.equal(result.counts.received, 4);
  assert(maximumFrame > 1024);
  assert.equal((await listener.done).outcome, 'complete');
  await listener.cleanup();
  assert.deepEqual(closed.sort(), ['a', 'b']);
  assert.equal(waiters.size, 0);
});

test('fact stream is finite, alternating, unique acknowledgements not assumed admissions', async () => {
  const requests = [];
  const ctx = context(async request => {
    requests.push(request);
    return ok({ proposal_id: key('defghijklmnopqrs'[requests.length - 1]) });
  });
  const result = await runFacts(ctx, { action: 'role-stream', network: 'test', timeoutMs: 100,
    count: 16, target: D, participantIds: [A, B] });
  assert.equal(requests.length, 16);
  assert(requests.every((r, i) => r.role === (i % 2 ? 'controller' : 'member')));
  assert.equal(result.distinctAcknowledgedIds, 16);
  assert.equal(result.admissionCount, null);
  assert.equal(result.status, 'acknowledged_not_convergence');
});

test('unknown fact mutation stops after one attempt', async () => {
  let writes = 0;
  const ctx = context(async () => { writes += 1; throw new Error('lost reply'); });
  await assert.rejects(runFacts(ctx, { action: 'role-stream', network: 'test', timeoutMs: 100,
    count: 16, target: D, participantIds: [A, B] }), error => {
    assert.equal(error.result.outcomeUnknown, 1); return true;
  });
  assert.equal(writes, 1);
});

test('canonical export uses fresh cursor and checks complete stable identity', async () => {
  const facts = [A, B].map(id => ({ id, content: { mesh_context: contextId }, signature: 'mock' }));
  const ctx = context(async request => {
    if (request.op === 'semantic_state_identity') return ok({ semantic_state_identity: identity(2) });
    assert.equal(request.op, 'semantic_fact_page_export');
    assert.equal(request.request.cursor, null);
    return ok({ semantic_fact_page: { context_id: contextId, facts, complete: true, next_cursor: null } });
  });
  const result = await runFacts(ctx, { action: 'export', network: 'test', timeoutMs: 100,
    contextId, expectedMaxFacts: 2, maxPages: 2, maxFacts: 2, maxEncodedBytes: 4096 });
  assert.equal(result.factCount, 2);
  assert.equal(result.uniqueIdCount, 2);
  assert.deepEqual(result.facts, facts);
});

test('convergence waits for exact observed identity without a mutation', async () => {
  let reads = 0;
  const ctx = context(async request => {
    assert.equal(request.op, 'semantic_state_identity');
    return ok({ semantic_state_identity: identity(reads++ === 0 ? 0 : 2) });
  });
  const result = await runFacts(ctx, { action: 'converge', network: 'test', timeoutMs: 100,
    expectedIdentity: identity(2), intervalMs: 1, maxObservations: 2 });
  assert.equal(result.observations, 2);
  assert.equal(result.matched, true);
});
