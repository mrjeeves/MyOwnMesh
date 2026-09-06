// Public daemon RPC workloads only. No signing, automatic import, or mutation retry.
// Loaded by live-device-peer.mjs; all deadlines use that controller's local clock.
import { Buffer } from 'node:buffer';

const BASE32 = 'abcdefghijklmnopqrstuvwxyz234567';

function check(ok, message) {
  if (!ok) throw new Error(message);
}

function integer(value, name, minimum = 1) {
  check(Number.isSafeInteger(value) && value >= minimum, `${name} must be an integer >= ${minimum}`);
  return value;
}

function text(value, name) {
  check(typeof value === 'string' && value.length > 0, `${name} is required`);
  return value;
}

// Canonical 32-byte lowercase BASE32_NOPAD. FactId Ord compares decoded bytes.
// Device key validity remains the production daemon's Ed25519 check, not this codec.
function idBytes(value) {
  check(typeof value === 'string' && /^[a-z2-7]{52}$/.test(value), 'noncanonical 32-byte ID');
  const bytes = [];
  let bits = 0;
  let accumulator = 0;
  for (const char of value) {
    accumulator = (accumulator << 5) | BASE32.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((accumulator >> bits) & 255);
      accumulator &= (1 << bits) - 1;
    }
  }
  check(bytes.length === 32 && accumulator === 0, 'noncanonical ID padding bits');
  return Buffer.from(bytes);
}

function identity(value) {
  check(value && typeof value === 'object', 'missing semantic identity');
  idBytes(value.context_id);
  integer(value.admitted_fact_count, 'admitted_fact_count', 0);
  integer(value.unresolved_fact_count, 'unresolved_fact_count', 0);
  for (const field of ['projection_commitment', 'state_commitment']) {
    check(Array.isArray(value[field]) && value[field].length === 32
      && value[field].every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255),
    `invalid ${field}`);
  }
  return {
    context_id: value.context_id,
    admitted_fact_count: value.admitted_fact_count,
    unresolved_fact_count: value.unresolved_fact_count,
    projection_commitment: value.projection_commitment,
    state_commitment: value.state_commitment,
  };
}

function sameIdentity(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function remaining(ctx) {
  check(!ctx.signal.aborted, 'facts action aborted');
  const value = ctx.deadlineMs - ctx.monoMs();
  check(Number.isFinite(value) && value > 0, 'facts action deadline exceeded');
  return value;
}

async function pause(ctx, intervalMs) {
  const duration = Math.min(intervalMs, remaining(ctx));
  await new Promise((resolve, reject) => {
    const aborted = () => {
      clearTimeout(timer);
      ctx.signal.removeEventListener('abort', aborted);
      reject(new Error('facts action aborted'));
    };
    const timer = setTimeout(() => {
      ctx.signal.removeEventListener('abort', aborted);
      resolve();
    }, duration);
    ctx.signal.addEventListener('abort', aborted, { once: true });
    if (ctx.signal.aborted) aborted();
  });
}

async function observe(ctx, command) {
  const timeout = Math.min(command.timeoutMs, remaining(ctx));
  const startedMs = ctx.monoMs();
  const reply = await ctx.rpc({ op: 'semantic_state_identity', network: command.network }, timeout);
  return {
    identity: identity(ctx.requireOk(reply, 'semantic identity').semantic_state_identity),
    startedMs,
    observedMs: ctx.monoMs(),
  };
}

async function streamRoles(ctx, command) {
  integer(command.count, 'count');
  idBytes(command.target);
  check(Array.isArray(command.participantIds) && command.participantIds.length > 0,
    'participantIds must list the participating devices');
  command.participantIds.forEach(idBytes);
  check(!command.participantIds.includes(command.target), 'role target must not be a participant');
  check(command.mfaCode == null || typeof command.mfaCode === 'string', 'invalid mfaCode');
  const result = {
    action: command.action, status: 'running', requested: command.count,
    attempted: 0, acknowledged: 0, refused: 0, outcomeUnknown: 0,
    // A proposal acknowledgement is not counterpart receipt or proof of Inserted.
    admissionCount: null, distinctAcknowledgedIds: 0, proposalIds: [], requests: [],
    startedMs: ctx.monoMs(),
  };
  const ids = new Set();
  try {
    for (let index = 0; index < command.count; index += 1) {
      const timeout = Math.min(command.timeoutMs, remaining(ctx));
      const role = index % 2 === 0 ? 'member' : 'controller';
      const sample = { index, role, startedMs: ctx.monoMs(), status: 'outcome_unknown' };
      result.attempted += 1;
      let reply;
      try {
        reply = await ctx.rpc({
          op: 'governance_propose_role_grant', network: command.network,
          target: command.target, role, mfa_code: command.mfaCode ?? null,
        }, timeout);
      } catch {
        sample.durationMs = ctx.monoMs() - sample.startedMs;
        result.outcomeUnknown += 1;
        result.requests.push(sample);
        await ctx.emit({ kind: 'fact_request', ...sample });
        throw new Error('mutation outcome unknown; stopped without retry; reconcile canonical export');
      }
      sample.durationMs = ctx.monoMs() - sample.startedMs;
      if (reply?.ok === false) {
        // Refusal may occur after a commit/publication boundary. Never infer rollback.
        sample.status = 'refused';
        result.refused += 1;
        result.requests.push(sample);
        await ctx.emit({ kind: 'fact_request', ...sample });
        throw new Error('governance refused; stopped without retry; commit state requires reconciliation');
      }
      let proposalId;
      try {
        proposalId = ctx.requireOk(reply, 'role grant').proposal_id;
        idBytes(proposalId);
      } catch {
        result.outcomeUnknown += 1;
        result.requests.push(sample);
        await ctx.emit({ kind: 'fact_request', ...sample });
        throw new Error('mutation reply lacks a valid fact ID; stopped without retry');
      }
      sample.status = 'acknowledged';
      sample.proposalId = proposalId;
      result.acknowledged += 1;
      result.proposalIds.push(proposalId);
      result.requests.push(sample);
      const duplicate = ids.has(proposalId);
      ids.add(proposalId);
      result.distinctAcknowledgedIds = ids.size;
      await ctx.emit({ kind: 'fact_request', ...sample });
      check(!duplicate, 'duplicate proposal ID; generation stopped, not counted as new admission');
    }
    result.status = 'acknowledged_not_convergence';
  } catch (error) {
    result.status = result.outcomeUnknown ? 'outcome_unknown' : 'stopped';
    error.result = result;
    throw error;
  } finally {
    result.wallMs = ctx.monoMs() - result.startedMs;
    result.acknowledgementsPerSecond = result.wallMs > 0
      ? result.acknowledged * 1000 / result.wallMs : null;
    // Never include request MFA or raw error/reply strings in evidence.
    await ctx.emit({ kind: 'fact_stream_summary', ...result });
  }
  return result;
}

async function convergence(ctx, command) {
  const expected = identity(command.expectedIdentity);
  check(expected.unresolved_fact_count === 0, 'convergence requires an unresolved-free expected identity');
  integer(command.intervalMs, 'intervalMs');
  check(command.intervalMs <= 2_147_483_647, 'intervalMs exceeds the Node timer range');
  integer(command.maxObservations, 'maxObservations');
  const startedMs = ctx.monoMs();
  for (let index = 0; index < command.maxObservations; index += 1) {
    const observation = await observe(ctx, command);
    const matched = sameIdentity(observation.identity, expected);
    await ctx.emit({ kind: 'fact_convergence_observation', index, matched, ...observation });
    if (matched) return {
      action: command.action, matched: true, observations: index + 1, ...observation,
      observationUpperBoundMs: observation.observedMs - startedMs,
      measurement: 'controller-local action-start to observed identity match; includes polling and RPC',
    };
    if (index + 1 < command.maxObservations) await pause(ctx, command.intervalMs);
  }
  throw new Error('identity did not converge within maxObservations; no mutations attempted');
}

async function exportFacts(ctx, command) {
  idBytes(command.contextId);
  integer(command.expectedMaxFacts, 'expectedMaxFacts', 0);
  for (const key of ['maxPages', 'maxFacts', 'maxEncodedBytes']) integer(command[key], key);
  check(Number.isSafeInteger(command.maxPages * command.maxEncodedBytes), 'export byte bound overflows');
  const before = await observe(ctx, command);
  check(before.identity.context_id === command.contextId, 'export context mismatch');
  const expectedCount = before.identity.admitted_fact_count + before.identity.unresolved_fact_count;
  check(Number.isSafeInteger(expectedCount) && expectedCount <= command.expectedMaxFacts,
    'identity exceeds explicit export fact bound');
  const facts = [];
  const pages = [];
  const ids = new Set();
  let cursor = null;
  let previousId = null;
  let complete = false;
  for (let index = 0; index < command.maxPages; index += 1) {
    const timeout = Math.min(command.timeoutMs, remaining(ctx));
    const startedMs = ctx.monoMs();
    const reply = await ctx.rpc({ op: 'semantic_fact_page_export', network: command.network,
      request: { context_id: command.contextId, cursor,
        max_facts: command.maxFacts, max_encoded_bytes: command.maxEncodedBytes } }, timeout);
    const page = ctx.requireOk(reply, 'canonical export').semantic_fact_page;
    check(page && page.context_id === command.contextId && Array.isArray(page.facts)
      && typeof page.complete === 'boolean', 'invalid canonical page');
    check(page.facts.length <= command.maxFacts
      && facts.length + page.facts.length <= command.expectedMaxFacts, 'export fact bound exceeded');
    const pageJson = JSON.stringify(page);
    const jsonBytes = Buffer.byteLength(pageJson, 'utf8');
    check(jsonBytes <= command.maxEncodedBytes, 'returned page JSON exceeds byte bound');
    for (const fact of page.facts) {
      const bytes = idBytes(fact.id);
      check(!ids.has(fact.id) && (!previousId || Buffer.compare(previousId, bytes) < 0),
        'duplicate or nonadvancing FactId in export');
      check(fact.content?.mesh_context === command.contextId
        && typeof fact.signature === 'string', 'missing signed fact body/context');
      ids.add(fact.id);
      previousId = bytes;
      facts.push(fact);
    }
    if (page.complete) check(page.next_cursor === null, 'complete page has a continuation cursor');
    else {
      check(page.facts.length > 0 && page.next_cursor === page.facts.at(-1).id,
        'incomplete page did not advance to its last fact');
      idBytes(page.next_cursor);
    }
    const evidence = { index, cursor, nextCursor: page.next_cursor, complete: page.complete,
      factCount: page.facts.length, jsonBytes, durationMs: ctx.monoMs() - startedMs };
    pages.push(evidence);
    // Preserve actual returned bodies. This string is reserialization, not original wire bytes.
    await ctx.emit({ kind: 'fact_export_page', ...evidence, pageJson,
      byteMeasurement: 'utf8_json_reserialization_not_ipc_frame' });
    cursor = page.next_cursor;
    if (page.complete) { complete = true; break; }
  }
  check(complete, 'export maxPages exhausted before complete');
  const after = await observe(ctx, command);
  check(sameIdentity(before.identity, after.identity), 'semantic identity changed during export; sweep invalid');
  check(facts.length === expectedCount, 'export count does not equal admitted plus unresolved identity');
  return { action: command.action, complete: true, identity: after.identity,
    factCount: facts.length, uniqueIdCount: ids.size, facts, pages,
    unresolvedFactCount: after.identity.unresolved_fact_count,
    signatureVerification: 'daemon canonical export; no independent verifier in this controller',
    totalPageJsonBytes: pages.reduce((sum, page) => sum + page.jsonBytes, 0),
    wallMs: ctx.monoMs() - before.startedMs };
}

/**
 * Required common command fields: action, network, timeoutMs.
 * role-stream: count, target, participantIds, optional mfaCode (never logged).
 * identity: one read. converge: expectedIdentity, intervalMs, maxObservations.
 * export: contextId, expectedMaxFacts (includes unresolved), maxPages,
 *         maxFacts and maxEncodedBytes. Caller must stop writers before export.
 * Failures throw; role-stream additionally emits/attaches partial result evidence.
 * No action imports facts. Assisted import belongs to an explicit main RPC command.
 */
export async function runFacts(ctx, command) {
  text(command.network, 'network');
  integer(command.timeoutMs, 'timeoutMs');
  check(command.timeoutMs <= 2_147_483_647, 'timeoutMs exceeds the Node timer range');
  remaining(ctx);
  switch (command.action) {
    case 'role-stream': return streamRoles(ctx, command);
    case 'identity': {
      const observation = await observe(ctx, command);
      await ctx.emit({ kind: 'fact_identity', ...observation });
      return { action: command.action, ...observation };
    }
    case 'converge': return convergence(ctx, command);
    case 'export': return exportFacts(ctx, command);
    default: throw new Error('unsupported facts action');
  }
}
