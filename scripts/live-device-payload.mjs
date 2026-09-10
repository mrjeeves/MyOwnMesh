// Public daemon IPC only. No console output: ctx.emit and returned results are
// the evidence boundary. Never include raw IPC replies, errors.
//
// Commands share network, channel, peer (full canonical key), run_id, samples,
// bytes, timeout_ms and lifetime_ms. echo_listen/echo_run use channel_send_to.
// Listen actions return {result, cleanup, done}; main owns/joins that lifetime
// and serializes only result/done. Other actions return a JSON-safe summary.
// bytes counts ASCII application body bytes, excluding tags/JSON. Each message
// carries all tags. Sequential goodput is NOT saturated transport throughput.
// Use a fresh run_id for each experiment and identical sample/byte settings on
// both ends. Start the listener first; its peer is the sender's full key.
// Reserve controller time beyond lifetime_ms for subscription cleanup.
// Optional diagnostic_timing (strict boolean, generic echo actions only) adds
// local numeric phase evidence to the terminal summary, never to mesh packets.

import { createHash } from 'node:crypto';

const PROTOCOL = 'myownmesh.live-payload.v1';
const MAX_SAMPLES = 10_000;
const MAX_BODY_BYTES = 8_192;
const MAX_TOTAL_BYTES = 16 * 1024 * 1024;
const MAX_LIFETIME_MS = 300_000;
// A row is seq plus 13 local offsets and a numeric observer-failure flag (or
// null). Each finite nonnegative number <= MAX_SAFE_INTEGER has <= 24 JSON
// characters: 15 * 25 + brackets < 512.
// The bound includes commas between rows; columns/metadata have a separate 2KiB
// allowance. At 10,000 rows this is <= 5,132,050 bytes of additional evidence.
const TIMING_ROW_BYTES = 512;
const TIMING_COLUMNS = Object.freeze(['seq', 'attempt_begin', 'callback_entry',
  'request_validated', 'echo_send_begin', 'rpc_call_begin', 'rpc_enqueue',
  'rpc_dequeue', 'rpc_connection_ready', 'rpc_write_completion_observed', 'rpc_reply_observed',
  'send_ack', 'send_outcome_unknown', 'echo_validated', 'rpc_observer_failed']);
const T = Object.freeze(Object.fromEntries(TIMING_COLUMNS.map((name, i) => [name, i])));
const RPC_TIMING_COLUMNS = Object.freeze({ enqueued: T.rpc_enqueue, dequeued: T.rpc_dequeue,
  connection_ready: T.rpc_connection_ready,
  write_completion_observed: T.rpc_write_completion_observed,
  reply_observed: T.rpc_reply_observed });
const RPC_TIMING_ORDER = Object.freeze(Object.keys(RPC_TIMING_COLUMNS));
const KEY = /^[a-z2-7]{51}[aq]$/;
const PACKET_KEYS = ['body', 'channel', 'kind', 'network', 'protocol', 'run_id', 'seq'];
const TIERS = new Set(['steady', 'wake_probe', 'ice_watchdog', 'ice_restart', 'stop_start']);
const RESOURCE_DIMENSIONS = new Set(['AccountedMemoryBytes', 'QueuedBytes', 'SocketOrHandle',
  'NativeTransportObject', 'WorkerOrTask', 'CallbackOrScheduledWork', 'StorageBytes',
  'StorageObject', 'RelayOrProviderAllocation', 'ParsingOrCpuWork', 'OpaqueDependencyResidual']);
const FIXED_REFUSALS = new Set(['network has been torn down', 'transport: data channel not open',
  'transport: peer send timed out']);

class PayloadError extends Error {
  constructor(stage, category, diagnostic = undefined) {
    super(`${stage}: ${category}`);
    this.stage = stage;
    this.category = category;
    this.diagnostic = diagnostic;
  }
}

function fail(stage, category) { throw new PayloadError(stage, category); }
function failure(error, stage = 'payload') {
  return error instanceof PayloadError
    ? { stage: error.stage, category: error.category,
      ...(error.diagnostic === undefined ? {} : { daemon_diagnostic: error.diagnostic }) }
    : { stage, category: 'local_failure_details_redacted' };
}
function daemonDiagnostic(value) {
  // Error strings can contain peer-controlled text or local capabilities.
  // Only a complete, bounded, source-shaped grammar may escape redaction.
  if (typeof value !== 'string') return { kind: 'redacted_nonstring_error' };
  const bytes = Buffer.byteLength(value, 'utf8');
  const redacted = { kind: 'redacted_error', utf8_bytes: bytes,
    sha256: createHash('sha256').update(value).digest('hex') };
  if (bytes > 1024) return redacted;
  if (FIXED_REFUSALS.has(value)) return { kind: 'known_refusal', message: value };
  // channels.rs ResourcePressure uses Debug, including ResourceScopeId's
  // NonZeroU64 newtype. Display-shaped or appended free-form text is refused.
  const match = /^application gateway resource pressure: Pressure\(ResourcePressure \{ scope_id: ResourceScopeId\(([1-9][0-9]{0,19})\), authority: (Cleanup|Admitted|Speculative), dimension: ([A-Za-z]+), requested: (0|[1-9][0-9]{0,19}), in_use: (0|[1-9][0-9]{0,19}), capacity: (0|[1-9][0-9]{0,19}) \}\)$/.exec(value);
  if (!match || match[0] !== value || !RESOURCE_DIMENSIONS.has(match[3])) return redacted;
  const scalars = [match[1], match[4], match[5], match[6]].map(Number);
  // Reject an unrepresentable diagnostic rather than round any u64 identity.
  if (!scalars.every(Number.isSafeInteger)) return redacted;
  return { kind: 'resource_pressure', scope_id: scalars[0], authority: match[2],
    dimension: match[3], requested: scalars[1], in_use: scalars[2], capacity: scalars[3] };
}
function integer(value, min, max, label) {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    fail('preflight', `invalid_${label}`);
  }
  return value;
}
function text(value, max, label) {
  if (typeof value !== 'string' || value.length === 0
      || Buffer.byteLength(value, 'utf8') > max || /[\x00-\x1f]/.test(value)) {
    fail('preflight', `invalid_${label}`);
  }
  return value;
}
function key(value, label) {
  if (typeof value !== 'string' || !KEY.test(value)) fail('preflight', `invalid_${label}`);
  return value;
}
function prepare(ctx, command) {
  for (const name of ['rpc', 'subscribe', 'monoMs', 'emit']) {
    if (typeof ctx[name] !== 'function') fail('preflight', `missing_context_${name}`);
  }
  if (!ctx.signal || !Number.isFinite(ctx.deadlineMs)) fail('preflight', 'invalid_context_lifetime');
  if (Object.hasOwn(command, 'diagnostic_timing')
      && (typeof command.diagnostic_timing !== 'boolean'
        || !['echo_run', 'echo_listen'].includes(command.action))) {
    fail('preflight', 'invalid_diagnostic_timing');
  }
  const c = {
    action: command.action,
    network: text(command.network, 128, 'network'),
    channel: text(command.channel, 128, 'channel'),
    peer: key(command.peer, 'peer'),
    run_id: text(command.run_id, 80, 'run_id'),
    samples: integer(command.samples, 1, MAX_SAMPLES, 'samples'),
    bytes: integer(command.bytes, 1, MAX_BODY_BYTES, 'bytes'),
    timeout_ms: integer(command.timeout_ms, 1, 60_000, 'timeout_ms'),
    lifetime_ms: integer(command.lifetime_ms, 1, MAX_LIFETIME_MS, 'lifetime_ms'),
  };
  if (!/^[A-Za-z0-9_-]+$/.test(c.run_id)) fail('preflight', 'invalid_run_id');
  if (c.samples * c.bytes > MAX_TOTAL_BYTES) fail('preflight', 'total_workload_exceeds_bound');
  c.started = ctx.monoMs();
  c.invoked = c.started;
  c.deadline = Math.min(ctx.deadlineMs, c.started + c.lifetime_ms);
  if (ctx.signal.aborted || c.deadline <= c.started) fail('preflight', 'lifetime_unavailable');
  c.body = '0123456789abcdef'.repeat(Math.ceil(c.bytes / 16)).slice(0, c.bytes);
  if (command.diagnostic_timing === true) c.timing = { rows: [], sealed: false };
  return c;
}
function timingRow(c, seq) {
  if (!c.timing || c.timing.sealed || c.timing.rows.length >= c.samples) return null;
  const row = Array(TIMING_COLUMNS.length).fill(null);
  row[0] = seq;
  c.timing.rows.push(row);
  return row;
}
function timingMark(c, row, column, now) {
  if (!row || c.timing.sealed || row[column] !== null || typeof now !== 'number') return;
  const offset = now - c.invoked;
  if (Number.isFinite(offset) && offset >= 0 && offset <= Number.MAX_SAFE_INTEGER) {
    row[column] = offset;
  }
}
function timingEvidence(c) {
  if (!c.timing) return {};
  // Called only outside the measured loop / after receiver active work joins.
  c.timing.sealed = true;
  const rows = c.timing.rows;
  return { diagnostic_timing: { schema: 'echo_phase_timing/v1',
    role: c.action === 'echo_run' ? 'sender' : 'receiver',
    clock: 'controller_local_monotonic_offsets_from_command_invocation_ms',
    scope: 'controller_phases_not_network_arrival_or_remote_clock_or_physical_route_proof',
    rpc_scope: 'write_completion_observed_after_send_await_reply_observed_after_nextFrame_await_not_callback_or_parse_instants',
    rpc_phase_breakdown_complete: rows.length > 0 && rows.every(row => {
      if (row[T.rpc_observer_failed] !== 0) return false;
      const phases = [T.rpc_call_begin, ...Object.values(RPC_TIMING_COLUMNS)].map(i => row[i]);
      return phases.every((value, i) => value !== null && (i === 0 || value >= phases[i - 1]));
    }),
    columns: TIMING_COLUMNS, rows, row_limit: c.samples,
    row_json_bytes_bound: TIMING_ROW_BYTES,
    rows_json_bytes: Buffer.byteLength(JSON.stringify(rows), 'utf8'),
    evidence_json_bytes_bound: 2050 + c.samples * (TIMING_ROW_BYTES + 1) } };
}
function remaining(ctx, c, cap = c.timeout_ms) {
  const value = Math.min(cap, c.deadline - ctx.monoMs(), ctx.deadlineMs - ctx.monoMs());
  if (value < 1 || ctx.signal.aborted) fail('lifetime', 'cancelled_or_deadline');
  return Math.max(1, Math.floor(value));
}
async function rpc(ctx, c, request, stage, cap = c.timeout_ms, timing = null) {
  const timeout = remaining(ctx, c, cap);
  if (stage === 'channel_send') {
    c.last_send_encoding = { operation: request.op,
      packet_json_bytes: Buffer.byteLength(JSON.stringify(request.payload), 'utf8'),
      request_json_bytes: Buffer.byteLength(JSON.stringify(request), 'utf8'),
      scope: 'last_send_attempt_local_JSON_UTF8_excludes_JSONL_delimiter_not_native_wire_or_resource_claim' };
  }
  let reply, call;
  let observationOpen = true, observationFault = false;
  try {
    if (timing) {
      timingMark(c, timing, T.rpc_call_begin, ctx.monoMs());
      let nextObservation = 0;
      call = ctx.rpc(request, timeout, (phase, ms) => {
        if (!observationOpen) return;
        const column = typeof phase === 'string' && Object.hasOwn(RPC_TIMING_COLUMNS, phase)
          ? RPC_TIMING_COLUMNS[phase] : null;
        if (column === null || typeof ms !== 'number' || !Number.isFinite(ms)
            || ms < c.invoked || ms - c.invoked > Number.MAX_SAFE_INTEGER) {
          observationFault = true;
          return;
        }
        // Clock equality cannot establish callback order. Latch any skipped,
        // swapped or duplicate phase, without changing the operation outcome
        // or overwriting the first retained timestamp for a recognized phase.
        if (phase !== RPC_TIMING_ORDER[nextObservation]) observationFault = true;
        else nextObservation += 1;
        timingMark(c, timing, column, ms);
      });
    } else call = ctx.rpc(request, timeout);
    reply = await call;
  }
  catch { fail(stage, 'transport_outcome_unknown'); }
  finally {
    observationOpen = false;
    if (timing) {
      // Retain the actual Promise: an async adapter would erase this getter.
      // An absent getter is unavailable evidence, never a completed breakdown.
      try {
        const failed = call?.timingObserverFailed;
        if (typeof failed === 'boolean') timing[T.rpc_observer_failed] = failed || observationFault ? 1 : 0;
        else if (observationFault) timing[T.rpc_observer_failed] = 1;
      } catch { timing[T.rpc_observer_failed] = 1; }
    }
  }
  if (!reply || typeof reply.ok !== 'boolean') fail(stage, 'invalid_reply_outcome_unknown');
  if (!reply.ok) throw new PayloadError(stage, 'daemon_reported_failure', daemonDiagnostic(reply.error));
  return reply.data;
}
function packet(c, seq, kind) {
  return { protocol: PROTOCOL, network: c.network, channel: c.channel,
    kind, run_id: c.run_id, seq, body: c.body };
}
function validPacket(value, c, kind) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join('|') === PACKET_KEYS.join('|')
    && value.protocol === PROTOCOL && value.kind === kind && value.run_id === c.run_id
    && value.network === c.network && value.channel === c.channel
    && Number.isSafeInteger(value.seq) && value.seq >= 0 && value.seq < c.samples
    && value.body === c.body;
}
function counts() {
  return { attempted: 0, sent: 0, received: 0, lost: 0, duplicate: 0,
    mismatch: 0, late: 0, busy_dropped: 0, send_outcome_unknown: 0 };
}
function bump(stats, name) { stats[name] = Math.min(Number.MAX_SAFE_INTEGER, stats[name] + 1); }
function summary(ctx, c, stats, outcome, extra = {}) {
  const end = c.finished ?? ctx.monoMs();
  const elapsed = Math.max(0, end - c.invoked);
  const sampleElapsed = Math.max(0, end - c.started);
  return { kind: 'payload_summary', action: c.action, run_id: c.run_id,
    network: c.network, channel: c.channel, peer: c.peer, samples: c.samples,
    body_bytes_per_sample: c.bytes, body_sha256: createHash('sha256').update(c.body).digest('hex'),
    last_send_encoding: c.last_send_encoding ?? null,
    counts: { ...stats }, not_attempted: c.samples - stats.attempted,
    verified_body_bytes: stats.received * c.bytes, elapsed_ms: elapsed,
    sample_loop_elapsed_ms: sampleElapsed,
    sequential_app_goodput_bytes_per_second: elapsed > 0 ? stats.received * c.bytes * 1000 / elapsed : null,
    goodput_scope: 'sequential_echo_body_bytes_over_setup_and_sample_workload_including_local_IPC_excluding_evidence_and_teardown',
    loss_scope: 'attempts_without_verified_on_time_echo_not_diagnosed_network_packet_loss',
    clock: 'controller_local_monotonic', nomination_available: false,
    outcome, ...extra };
}
async function channelSend(ctx, c, value, timing = null) {
  try {
    const data = await rpc(ctx, c, { op: 'channel_send_to', network: c.network,
      channel: c.channel, peer: c.peer, payload: value }, 'channel_send', c.timeout_ms, timing);
    if (data?.sent !== true) fail('channel_send', 'missing_send_ack_outcome_unknown');
    if (timing) timingMark(c, timing, T.send_ack, ctx.monoMs());
  } catch (error) {
    if (timing) timingMark(c, timing, T.send_outcome_unknown, ctx.monoMs());
    throw error;
  }
}
async function observePeers(ctx, c) {
  try {
    const data = await rpc(ctx, c, { op: 'peers_list', network: c.network }, 'peers_list');
    if (!Array.isArray(data?.peers)) fail('peers_list', 'invalid_peers');
    const peers = [];
    for (const value of data.peers.slice(0, 64)) {
      if (!KEY.test(value?.device_id ?? '') || typeof value.status !== 'string'
          || value.status.length > 40 || value.tier === null || typeof value.tier !== 'object'
          || Array.isArray(value.tier) || Object.keys(value.tier).length !== 1
          || !TIERS.has(value.tier.kind) || typeof value.authenticated !== 'boolean') {
        fail('peers_list', 'unsupported_peer_shape');
      }
      // Deliberate allowlist: never retain labels, verification codes or
      // capabilities. Pair presence does not prove nomination or actual hops.
      peers.push({ device_id: value.device_id, status: value.status, tier: { kind: value.tier.kind },
        authenticated: value.authenticated, selected_pair_present: value.selected_pair != null });
    }
    return { available: true, total_rows: data.peers.length, truncated: data.peers.length > 64,
      peers, physical_hop_proof: false, nomination_available: false };
  } catch (error) {
    return { available: false, failure: failure(error), physical_hop_proof: false };
  }
}
function fullEvent(event, c, kind) {
  return event?.kind === 'channel_inbound' && event.network === c.network
    && event.channel === c.channel && event.from === c.peer && validPacket(event.payload, c, kind);
}
function waiter(ctx, ms) {
  let finish;
  let settled = false;
  const promise = new Promise(resolve => { finish = resolve; });
  const settle = value => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    ctx.signal.removeEventListener('abort', abort);
    finish(value);
  };
  const abort = () => settle(false);
  const timer = setTimeout(abort, ms);
  ctx.signal.addEventListener('abort', abort, { once: true });
  if (ctx.signal.aborted) abort();
  return { promise, settle };
}

async function echoListen(ctx, c) {
  const stats = counts();
  const seen = new Set();
  let stopped = false;
  let outcome = 'listening';
  let errorRecord = null;
  let queued = null;
  let active = null;
  let ready = false;
  let timer = null;
  let unsubscribe;
  let cleanupPromise;
  let resolveDone;
  const done = new Promise(resolve => { resolveDone = resolve; });
  const cleanup = () => {
    if (cleanupPromise) return cleanupPromise;
    stopped = true;
    queued = null;
    clearTimeout(timer);
    ctx.signal.removeEventListener('abort', abort);
    cleanupPromise = (async () => {
      try { await unsubscribe(); } catch { outcome = 'subscription_cleanup_failed'; }
      if (active) await active;
      stats.lost = stats.received - stats.sent;
      const result = summary(ctx, c, stats, outcome === 'listening' ? 'stopped' : outcome,
        { counter_scope: 'responder_received_requests_and_attempted_echo_replies',
          failure: errorRecord,
          not_attempted: c.samples - stats.received,
          sequential_app_goodput_bytes_per_second: null,
          loss_scope: 'verified_requests_without_acknowledged_echo_send' });
      Object.assign(result, timingEvidence(c));
      resolveDone(result);
      return result;
    })();
    return cleanupPromise;
  };
  const process = async () => {
    while (queued) {
      const value = c.timing ? queued.value : queued;
      const timing = c.timing ? queued.timing : null;
      queued = null;
      if (stopped || ctx.signal.aborted || ctx.monoMs() >= c.deadline) break;
      stats.attempted += 1;
      if (timing) timingMark(c, timing, T.echo_send_begin, ctx.monoMs());
      try {
        await channelSend(ctx, c, packet(c, value.seq, 'echo'), timing);
        stats.sent += 1;
      } catch (error) {
        stats.send_outcome_unknown += 1;
        errorRecord = failure(error, 'echo_send');
        outcome = 'echo_send_outcome_unknown';
        stopped = true;
        break;
      }
    }
  };
  const pump = () => {
    if (!ready || stopped || active || !queued) return;
    // Defer until active owns this task, including synchronous RPC refusal.
    active = Promise.resolve().then(process).finally(() => {
      active = null;
      if (stopped || stats.sent === c.samples) {
        if (!stopped) outcome = 'complete';
        // Cleanup joins only other work, never its own completion callback.
        void cleanup();
      } else pump();
    });
  };
  const onEvent = event => {
    const arrived = c.timing ? ctx.monoMs() : null;
    if (stopped || ctx.signal.aborted || ctx.monoMs() >= c.deadline) return;
    if (!fullEvent(event, c, 'request')) { bump(stats, 'mismatch'); return; }
    const value = event.payload;
    if (seen.has(value.seq)) { bump(stats, 'duplicate'); return; }
    if (queued) { bump(stats, 'busy_dropped'); return; }
    seen.add(value.seq);
    stats.received += 1;
    const timing = timingRow(c, value.seq);
    if (timing) {
      timingMark(c, timing, T.callback_entry, arrived);
      timingMark(c, timing, T.request_validated, ctx.monoMs());
    }
    queued = c.timing ? { value, timing } : value;
    pump();
  };
  // Main's subscribe resolves only after the receiver is installed.
  unsubscribe = await ctx.subscribe(c.network, c.channel, onEvent);
  if (typeof unsubscribe !== 'function') fail('subscribe', 'missing_cleanup');
  const abort = () => { outcome = 'cancelled'; void cleanup(); };
  timer = setTimeout(() => { outcome = 'deadline'; void cleanup(); },
    Math.max(1, c.deadline - ctx.monoMs()));
  ctx.signal.addEventListener('abort', abort, { once: true });
  ready = true;
  if (ctx.signal.aborted) abort();
  else pump();
  return { result: { kind: 'echo_ready', run_id: c.run_id, network: c.network,
    channel: c.channel, peer: c.peer, deadline_ms: c.deadline }, cleanup, done };
}

async function echoRun(ctx, c) {
  const stats = counts();
  const rtts = [];
  const seen = new Set();
  let pending = null;
  let unsubscribe = null;
  let outcome = 'complete';
  let errorRecord = null;
  let routeBefore = null;
  const accept = value => {
    if (!validPacket(value, c, 'echo') || value.seq >= stats.attempted) {
      bump(stats, 'mismatch'); return;
    }
    if (seen.has(value.seq)) { bump(stats, 'duplicate'); return; }
    seen.add(value.seq);
    const now = ctx.monoMs();
    if (!pending || pending.seq !== value.seq || now >= pending.expires) {
      bump(stats, 'late'); return;
    }
    const rtt = now - pending.started;
    if (!Number.isFinite(rtt) || rtt < 0) { bump(stats, 'mismatch'); return; }
    stats.received += 1;
    rtts.push({ seq: value.seq, rtt_ms: rtt, verified_at_workload_ms: now - c.started });
    if (pending.timing) timingMark(c, pending.timing, T.echo_validated, now);
    pending.wait.settle(true);
  };
  try {
    unsubscribe = await ctx.subscribe(c.network, c.channel, event => {
      if (!fullEvent(event, c, 'echo')) { bump(stats, 'mismatch'); return; }
      accept(event.payload);
    });
    if (typeof unsubscribe !== 'function') fail('subscribe', 'missing_cleanup');
    routeBefore = await observePeers(ctx, c);
    c.started = ctx.monoMs();
    for (let seq = 0; seq < c.samples; seq += 1) {
      const duration = remaining(ctx, c);
      const started = ctx.monoMs();
      pending = { seq, started, expires: started + duration, wait: waiter(ctx, duration) };
      stats.attempted += 1;
      if (c.timing) {
        pending.timing = timingRow(c, seq);
        timingMark(c, pending.timing, T.attempt_begin, started);
      }
      const value = packet(c, seq, 'request');
      try {
        await channelSend(ctx, c, value, pending.timing);
        stats.sent += 1;
      } catch (error) {
        stats.send_outcome_unknown += 1;
        pending.wait.settle(false);
        outcome = 'send_outcome_unknown';
        errorRecord = failure(error, 'send');
        break; // Never retry a possibly written message.
      }
      const received = await pending.wait.promise;
      pending = null;
      if (!received && (ctx.signal.aborted || ctx.monoMs() >= c.deadline)) {
        outcome = 'cancelled_or_deadline';
        break;
      }
    }
  } catch (error) {
    outcome = 'failed'; errorRecord = failure(error);
  } finally {
    c.finished = ctx.monoMs();
    pending?.wait.settle(false);
    pending = null;
    if (unsubscribe) {
      try { await unsubscribe(); }
      catch { outcome = 'subscription_cleanup_failed'; }
    }
  }
  stats.lost = stats.attempted - stats.received;
  if (outcome === 'complete' && stats.lost !== 0) outcome = 'completed_with_unverified_samples';
  const routeAfter = await observePeers(ctx, c);
  for (const sample of rtts) {
    await ctx.emit({ kind: 'payload_rtt', run_id: c.run_id, ...sample,
      body_bytes: c.bytes, clock: 'controller_local_monotonic' });
  }
  return summary(ctx, c, stats, outcome, { rtt_observations: rtts, failure: errorRecord,
    ...timingEvidence(c),
    first_verified_echo_ms: rtts[0]?.verified_at_workload_ms ?? null,
    first_verified_echo_scope: 'from_sample_loop_start_excluding_setup',
    route_observations: { before: routeBefore, after: routeAfter },
    counter_scope: 'sender_attempts_send_acknowledgements_and_verified_on_time_echoes' });
}

export async function runPayload(ctx, command) {
  try {
    const c = prepare(ctx, command);
    switch (c.action) {
      case 'echo_listen': return await echoListen(ctx, c);
      case 'echo_run': return await echoRun(ctx, c);
      default: fail('preflight', 'unsupported_payload_action');
    }
  } catch (error) {
    if (error instanceof PayloadError) throw error;
    fail('payload', 'local_failure_details_redacted');
  }
}
