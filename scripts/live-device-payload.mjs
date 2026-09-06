// Public daemon IPC only. No console output: ctx.emit and returned results are
// the evidence boundary. Never include raw IPC replies, errors or relay handles.
//
// Commands share network, channel, peer (full canonical key), run_id, samples,
// bytes, timeout_ms and lifetime_ms. echo_listen/echo_run use channel_send_to.
// relay_echo_listen/relay_echo_run perform accept/open, exact byte-array echoes,
// and close; both relay actions also require relay (full canonical key).
// Listen actions return {result, cleanup, done}; main owns/joins that lifetime
// and serializes only result/done. Other actions return a JSON-safe summary.
// bytes counts ASCII application body bytes, excluding tags/JSON. Each message
// carries all tags. Sequential goodput is NOT saturated transport throughput.
// Use a fresh run_id for each experiment and identical sample/byte settings on
// both ends. Start the listener first; its peer is the sender's full key.
// Reserve controller time beyond lifetime_ms for cleanup. A relay responder
// waits for a tagged finish after the last echo; no unverified close is hidden.

import { createHash } from 'node:crypto';

const PROTOCOL = 'myownmesh.live-payload.v1';
const MAX_SAMPLES = 10_000;
const MAX_BODY_BYTES = 8_192;
const MAX_TOTAL_BYTES = 16 * 1024 * 1024;
const MAX_LIFETIME_MS = 300_000;
const KEY = /^[a-z2-7]{51}[aq]$/;
const PACKET_KEYS = ['body', 'channel', 'kind', 'network', 'protocol', 'run_id', 'seq'];

class PayloadError extends Error {
  constructor(stage, category) {
    super(`${stage}: ${category}`);
    this.stage = stage;
    this.category = category;
  }
}

function fail(stage, category) { throw new PayloadError(stage, category); }
function failure(error, stage = 'payload') {
  return error instanceof PayloadError
    ? { stage: error.stage, category: error.category }
    : { stage, category: 'local_failure_details_redacted' };
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
  return c;
}
function remaining(ctx, c, cap = c.timeout_ms) {
  const value = Math.min(cap, c.deadline - ctx.monoMs(), ctx.deadlineMs - ctx.monoMs());
  if (value < 1 || ctx.signal.aborted) fail('lifetime', 'cancelled_or_deadline');
  return Math.max(1, Math.floor(value));
}
async function rpc(ctx, c, request, stage, cap = c.timeout_ms) {
  const timeout = remaining(ctx, c, cap);
  let reply;
  try { reply = await ctx.rpc(request, timeout); }
  catch { fail(stage, 'transport_outcome_unknown'); }
  if (!reply || typeof reply.ok !== 'boolean') fail(stage, 'invalid_reply_outcome_unknown');
  if (!reply.ok) fail(stage, 'daemon_reported_failure');
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
    counts: { ...stats }, not_attempted: c.samples - stats.attempted,
    verified_body_bytes: stats.received * c.bytes, elapsed_ms: elapsed,
    sample_loop_elapsed_ms: sampleElapsed,
    sequential_app_goodput_bytes_per_second: elapsed > 0 ? stats.received * c.bytes * 1000 / elapsed : null,
    goodput_scope: 'sequential_echo_body_bytes_over_setup_and_sample_workload_including_local_IPC_excluding_evidence_and_teardown',
    loss_scope: 'attempts_without_verified_on_time_echo_not_diagnosed_network_packet_loss',
    clock: 'controller_local_monotonic', nomination_available: false,
    outcome, ...extra };
}
async function channelSend(ctx, c, value) {
  const data = await rpc(ctx, c, { op: 'channel_send_to', network: c.network,
    channel: c.channel, peer: c.peer, payload: value }, 'channel_send');
  if (data?.sent !== true) fail('channel_send', 'missing_send_ack_outcome_unknown');
}
async function observePeers(ctx, c) {
  try {
    const data = await rpc(ctx, c, { op: 'peers_list', network: c.network }, 'peers_list');
    if (!Array.isArray(data?.peers)) fail('peers_list', 'invalid_peers');
    const peers = [];
    for (const value of data.peers.slice(0, 64)) {
      if (!KEY.test(value?.device_id ?? '') || typeof value.status !== 'string'
          || value.status.length > 40 || typeof value.tier !== 'string'
          || value.tier.length > 40 || typeof value.authenticated !== 'boolean') {
        fail('peers_list', 'unsupported_peer_shape');
      }
      // Deliberate allowlist: never retain labels, verification codes or
      // capabilities. Pair presence does not prove nomination or actual hops.
      peers.push({ device_id: value.device_id, status: value.status, tier: value.tier,
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
          not_attempted: c.samples - stats.received,
          sequential_app_goodput_bytes_per_second: null,
          loss_scope: 'verified_requests_without_acknowledged_echo_send' });
      resolveDone(result);
      return result;
    })();
    return cleanupPromise;
  };
  const process = async () => {
    while (queued) {
      const value = queued;
      queued = null;
      if (stopped || ctx.signal.aborted || ctx.monoMs() >= c.deadline) break;
      stats.attempted += 1;
      try {
        await channelSend(ctx, c, packet(c, value.seq, 'echo'));
        stats.sent += 1;
      } catch {
        stats.send_outcome_unknown += 1;
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
    if (stopped || ctx.signal.aborted || ctx.monoMs() >= c.deadline) return;
    if (!fullEvent(event, c, 'request')) { bump(stats, 'mismatch'); return; }
    const value = event.payload;
    if (seen.has(value.seq)) { bump(stats, 'duplicate'); return; }
    if (queued) { bump(stats, 'busy_dropped'); return; }
    seen.add(value.seq);
    stats.received += 1;
    queued = value;
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

async function echoRun(ctx, c, relaySession = null) {
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
    pending.wait.settle(true);
  };
  try {
    if (!relaySession) {
      unsubscribe = await ctx.subscribe(c.network, c.channel, event => {
        if (!fullEvent(event, c, 'echo')) { bump(stats, 'mismatch'); return; }
        accept(event.payload);
      });
      if (typeof unsubscribe !== 'function') fail('subscribe', 'missing_cleanup');
    }
    routeBefore = await observePeers(ctx, c);
    c.started = ctx.monoMs();
    for (let seq = 0; seq < c.samples; seq += 1) {
      const duration = remaining(ctx, c);
      const started = ctx.monoMs();
      pending = { seq, started, expires: started + duration, wait: waiter(ctx, duration) };
      stats.attempted += 1;
      const value = packet(c, seq, 'request');
      try {
        if (relaySession) await relaySend(ctx, c, relaySession, value);
        else await channelSend(ctx, c, value);
        stats.sent += 1;
      } catch (error) {
        stats.send_outcome_unknown += 1;
        pending.wait.settle(false);
        outcome = 'send_outcome_unknown';
        errorRecord = failure(error, 'send');
        break; // Never retry a possibly written message.
      }
      if (relaySession) {
        // One bounded receive per sent sample. Unexpected bytes terminate the
        // sequential relay run instead of silently consuming/retrying reads.
        const budget = pending.expires - ctx.monoMs();
        if (budget < 1) { outcome = 'relay_echo_deadline'; break; }
        accept(await relayReceive(ctx, c, relaySession, budget));
      }
      const received = await pending.wait.promise;
      pending = null;
      if (!received && (ctx.signal.aborted || ctx.monoMs() >= c.deadline)) {
        outcome = 'cancelled_or_deadline';
        break;
      }
      if (relaySession && !received) { outcome = 'relay_echo_unverified'; break; }
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
  // The responder must not close the relay merely because its last echo was
  // queued: acknowledge all verified echoes before its bounded terminal wait.
  if (relaySession && outcome === 'complete' && stats.received === c.samples) {
    try { await relaySend(ctx, c, relaySession, packet(c, c.samples - 1, 'finish')); }
    catch (error) { outcome = 'finish_outcome_unknown'; errorRecord = failure(error); }
  }
  const routeAfter = await observePeers(ctx, c);
  for (const sample of rtts) {
    await ctx.emit({ kind: 'payload_rtt', run_id: c.run_id, ...sample,
      body_bytes: c.bytes, clock: 'controller_local_monotonic' });
  }
  return summary(ctx, c, stats, outcome, { rtt_observations: rtts, failure: errorRecord,
    first_verified_echo_ms: rtts[0]?.verified_at_workload_ms ?? null,
    first_verified_echo_scope: 'from_sample_loop_start_excluding_setup',
    route_observations: { before: routeBefore, after: routeAfter },
    counter_scope: 'sender_attempts_send_acknowledgements_and_verified_on_time_echoes' });
}

function relayData(data, variant) {
  const value = data?.closed_relay?.[variant];
  if (!value || typeof value !== 'object') fail(`relay_${variant}`, 'invalid_reply');
  return value;
}
function relayIdentity(value) {
  for (const field of ['generation', 'allocation_epoch']) {
    integer(value[field], 1, Number.MAX_SAFE_INTEGER, `relay_${field}`);
  }
  return { generation: value.generation, allocation_epoch: value.allocation_epoch };
}
function checkRelayOwner(value, session) {
  const identity = relayIdentity(value);
  if (identity.generation !== session.generation || identity.allocation_epoch !== session.allocation_epoch) {
    fail('relay_reply', 'session_identity_mismatch');
  }
  if (value.handle !== session.handle) fail('relay_reply', 'handle_mismatch');
}
function relayPublic(session) {
  return { ...relayIdentity(session), session_id: session.session_id,
    peer: session.peer, relay: session.relay, max_frame_bytes: session.max_frame_bytes };
}
async function relayAcquire(ctx, c, command, accept) {
  const data = await rpc(ctx, c, accept
    ? { op: 'closed_relay_accept', network: c.network, wait_ms: remaining(ctx, c) }
    : { op: 'closed_relay_open', network: c.network, relay: key(command.relay, 'relay'), target: c.peer },
  accept ? 'relay_accept' : 'relay_open');
  const value = relayData(data, accept ? 'accepted' : 'opened');
  // Capture the handle first, so even malformed metadata receives one close
  // attempt rather than abandoning a capability returned by the daemon.
  if (typeof value.handle !== 'string' || value.handle.length === 0 || value.handle.length > 1024) {
    fail('relay_acquire', 'unusable_handle_outcome_unknown');
  }
  try {
    relayIdentity(value);
    if (value.peer !== c.peer || value.network !== c.network
        || value.relay !== key(command.relay, 'relay')
        || !Array.isArray(value.session_id) || value.session_id.length !== 16
        || value.session_id.some(b => !Number.isInteger(b) || b < 0 || b > 255)
        || !value.session_id.some(b => b !== 0)) fail('relay_acquire', 'session_metadata_mismatch');
    integer(value.max_frame_bytes, 1, 65_535, 'relay_max_frame_bytes');
    if (Math.max(encodePacket(packet(c, c.samples - 1, 'request')).length,
      encodePacket(packet(c, c.samples - 1, 'echo')).length) > value.max_frame_bytes) {
      fail('relay_acquire', 'tagged_payload_exceeds_frame');
    }
    return value;
  } catch (error) {
    let cleanup = 'close_outcome_unknown';
    try {
      const closed = await closeHandle(ctx, c, value.handle);
      if (closed.handle === value.handle) cleanup = 'close_acknowledged_metadata_untrusted';
    } catch { /* Do not repeat a possibly consuming close. */ }
    await ctx.emit({ kind: 'relay_acquire_refused', run_id: c.run_id,
      failure: failure(error), close_outcome: cleanup });
    throw error;
  }
}
function encodePacket(value) { return [...Buffer.from(JSON.stringify(value), 'utf8')]; }
async function relaySend(ctx, c, session, value) {
  const bytes = encodePacket(value);
  if (bytes.length > session.max_frame_bytes) fail('relay_send', 'payload_exceeds_frame');
  const answer = relayData(await rpc(ctx, c, { op: 'closed_relay_send',
    handle: session.handle, payload: bytes }, 'relay_send'), 'sent');
  checkRelayOwner(answer, session);
  if (answer.bytes !== bytes.length) fail('relay_send', 'byte_count_mismatch');
}
async function relayReceive(ctx, c, session, timeout = c.timeout_ms) {
  const wait = remaining(ctx, c, timeout);
  const answer = relayData(await rpc(ctx, c, { op: 'closed_relay_recv',
    handle: session.handle, wait_ms: wait }, 'relay_recv', wait), 'received');
  checkRelayOwner(answer, session);
  if (!Array.isArray(answer.payload) || answer.payload.length > session.max_frame_bytes
      || answer.payload.some(b => !Number.isInteger(b) || b < 0 || b > 255)) {
    fail('relay_recv', 'invalid_byte_payload');
  }
  try {
    const buffer = Buffer.from(answer.payload);
    const value = JSON.parse(buffer.toString('utf8'));
    if (!buffer.equals(Buffer.from(JSON.stringify(value), 'utf8'))) fail('relay_recv', 'nonexact_encoding');
    return value;
  } catch { fail('relay_recv', 'invalid_tagged_encoding'); }
}
async function closeHandle(ctx, c, handle) {
  // Cleanup is a separately bounded phase. Do not let a work cancellation skip
  // the single consuming close; main keeps RPC alive until cleanup is joined.
  // Never extend the controller deadline or retry an ambiguous close.
  const budget = Math.min(c.timeout_ms, ctx.deadlineMs - ctx.monoMs());
  if (budget < 1) fail('relay_close', 'deadline_before_close_attempt');
  let reply;
  try { reply = await ctx.rpc({ op: 'closed_relay_close', handle }, Math.floor(budget)); }
  catch { fail('relay_close', 'transport_outcome_unknown'); }
  if (reply?.ok !== true) fail('relay_close', 'close_outcome_unknown');
  return relayData(reply.data, 'closed');
}
async function relayClose(ctx, c, session) {
  try {
    const answer = await closeHandle(ctx, c, session.handle);
    checkRelayOwner(answer, session);
    return 'closed';
  } catch (error) {
    return error instanceof PayloadError && error.category === 'deadline_before_close_attempt'
      ? 'close_not_attempted_deadline' : 'close_outcome_unknown';
  }
}
async function relayRun(ctx, c, command) {
  const session = await relayAcquire(ctx, c, command, false);
  let result;
  let closeOutcome;
  try { result = await echoRun(ctx, c, session); }
  finally { closeOutcome = await relayClose(ctx, c, session); }
  return { ...result, relay_session: relayPublic(session), close_outcome: closeOutcome,
    workload_outcome: result.outcome,
    outcome: closeOutcome === 'closed' ? result.outcome : 'terminal_cleanup_unconfirmed' };
}
function relayListen(ctx, c, command) {
  let stopped = false;
  const stats = counts();
  let session;
  const abort = () => { stopped = true; };
  ctx.signal.addEventListener('abort', abort, { once: true });
  const done = (async () => {
    let outcome = 'complete';
    let errorRecord = null;
    let closeOutcome = 'not_acquired';
    try {
      session = await relayAcquire(ctx, c, command, true);
      await ctx.emit({ kind: 'relay_echo_ready', run_id: c.run_id, relay_session: relayPublic(session) });
      const seen = new Set();
      for (let i = 0; i < c.samples && !stopped; i += 1) {
        const value = await relayReceive(ctx, c, session);
        if (!validPacket(value, c, 'request')) { bump(stats, 'mismatch'); outcome = 'mismatch'; break; }
        if (seen.has(value.seq)) { bump(stats, 'duplicate'); outcome = 'duplicate'; break; }
        seen.add(value.seq);
        stats.received += 1;
        if (stopped) break;
        stats.attempted += 1;
        try { await relaySend(ctx, c, session, packet(c, value.seq, 'echo')); stats.sent += 1; }
        catch (error) { stats.send_outcome_unknown += 1; throw error; }
      }
      if (!stopped && stats.sent === c.samples) {
        const finish = await relayReceive(ctx, c, session);
        if (!validPacket(finish, c, 'finish') || finish.seq !== c.samples - 1) {
          bump(stats, 'mismatch'); outcome = 'finish_unverified';
        }
      }
      if (stopped) outcome = 'stopped';
    } catch (error) { outcome = 'failed'; errorRecord = failure(error); }
    finally {
      if (session) closeOutcome = await relayClose(ctx, c, session);
      ctx.signal.removeEventListener('abort', abort);
    }
    stats.lost = stats.received - stats.sent;
    if (closeOutcome !== 'closed' && session) outcome = 'terminal_cleanup_unconfirmed';
    return summary(ctx, c, stats, outcome, { failure: errorRecord, close_outcome: closeOutcome,
      relay_session: session ? relayPublic(session) : null,
      counter_scope: 'responder_received_requests_and_attempted_echo_replies',
      sequential_app_goodput_bytes_per_second: null,
      loss_scope: 'verified_requests_without_acknowledged_echo_send' });
  })();
  return { result: { kind: 'relay_accepting', run_id: c.run_id, deadline_ms: c.deadline },
    cleanup: async () => { stopped = true; return await done; }, done };
}

export async function runPayload(ctx, command) {
  try {
    const c = prepare(ctx, command);
    switch (c.action) {
      case 'echo_listen': return await echoListen(ctx, c);
      case 'echo_run': return await echoRun(ctx, c);
      case 'relay_echo_listen': key(command.relay, 'relay'); return relayListen(ctx, c, command);
      case 'relay_echo_run': key(command.relay, 'relay'); return await relayRun(ctx, c, command);
      default: fail('preflight', 'unsupported_payload_action');
    }
  } catch (error) {
    if (error instanceof PayloadError) throw error;
    fail('payload', 'local_failure_details_redacted');
  }
}
