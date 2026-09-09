import { readFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const testsDirectory = dirname(fileURLToPath(import.meta.url));
const clientSource = readFileSync(join(testsDirectory, "..", "src", "mesh-client.svelte.ts"), "utf8");
const networkSettingsSource = readFileSync(
  join(testsDirectory, "..", "src", "network-settings.ts"),
  "utf8",
);
const daemonWireSource = readFileSync(
  join(testsDirectory, "..", "..", "crates", "myownmesh", "src", "control", "wire.rs"),
  "utf8",
);
const tauriClientSource = readFileSync(
  join(testsDirectory, "..", "src-tauri", "src", "control_client.rs"),
  "utf8",
);

const expectedRequestVariants = [
  "Status",
  "NetworksList",
  "PeersList",
  "RosterList",
  "TopologySet",
  "IdentityShow",
  "IdentitySetLabel",
  "NetworkIdGenerate",
  "NetworkIdNormalize",
  "ConfigShow",
  "NetworkAdd",
  "NetworkCreateClosed",
  "NetworkImportClosed",
  "NetworkBootstrapExport",
  "SemanticFactPageExport",
  "SemanticFactPageImport",
  "SemanticStateIdentity",
  "SemanticRecentFacts",
  "NetworkRemove",
  "ForgetAllNetworks",
  "FactoryReset",
  "NetworkUpdate",
  "NetworkReconnect",
  "NetworkConnectPeer",
  "ServicesStatus",
  "ServicesSet",
  "EventsSubscribe",
  "TraceSubscribe",
  "RpcRegister",
  "RpcUnregister",
  "RpcRespond",
  "RpcStreamChunk",
  "RpcStreamEnd",
  "RpcCall",
  "RpcCallStream",
  "ChannelSubscribe",
  "ChannelUnsubscribe",
  "ChannelSendTo",
  "ChannelSendReliable",
  "ChannelSendAll",
  "CapabilitiesSet",
  "RealtimeFlowOpen",
  "RealtimeFlowClose",
  "RealtimePipe",
  "OpaqueFlowOpen",
  "OpaqueFlowChange",
  "OpaqueFlowClose",
  "OpaquePipe",
  "GovernanceProposeRoleGrant",
  "GovernanceProposeRoleRevoke",
  "GovernanceProposeEvict",
  "GovernanceMfaPrepare",
  "GovernanceMfaQuery",
  "GovernanceMfaRedeliver",
  "GovernanceMfaCommit",
  "GovernanceMfaAbort",
  "GovernanceMfaStatus",
  "GovernanceMfaDisable",
  "UpdateStatus",
  "UpdateCheck",
  "UpdateApply",
  "UpdateSetPrefs",
];

// Strip comments before inspecting Rust declarations. This keeps the census
// tied to enum/fixture structures rather than prose that happens to mention a
// request name or field.
function withoutRustComments(source) {
  let output = "";
  let state = "code";
  for (let index = 0; index < source.length; index += 1) {
    const current = source[index];
    const next = source[index + 1];
    if (state === "line_comment") {
      output += current === "\n" ? "\n" : " ";
      if (current === "\n") state = "code";
    } else if (state === "block_comment") {
      if (current === "*" && next === "/") {
        output += "  ";
        index += 1;
        state = "code";
      } else {
        output += current === "\n" ? "\n" : " ";
      }
    } else if (state === "string") {
      output += current;
      if (current === "\\") {
        output += next ?? "";
        index += 1;
      } else if (current === '"') {
        state = "code";
      }
    } else if (state === "char") {
      output += current;
      if (current === "\\") {
        output += next ?? "";
        index += 1;
      } else if (current === "'") {
        state = "code";
      }
    } else if (current === "/" && next === "/") {
      output += "  ";
      index += 1;
      state = "line_comment";
    } else if (current === "/" && next === "*") {
      output += "  ";
      index += 1;
      state = "block_comment";
    } else {
      output += current;
      if (current === '"') state = "string";
      if (current === "'") state = "char";
    }
  }
  return output;
}

function declarationBody(source, declaration) {
  const stripped = withoutRustComments(source);
  const marker = new RegExp(`(?:pub\\s+)?enum\\s+${declaration}\\b`);
  const match = marker.exec(stripped);
  assert.ok(match, `missing Rust enum ${declaration}`);
  const open = stripped.indexOf("{", match.index + match[0].length);
  assert.notEqual(open, -1, `${declaration} enum has no body`);
  let depth = 0;
  for (let index = open; index < stripped.length; index += 1) {
    if (stripped[index] === "{") depth += 1;
    if (stripped[index] === "}") {
      depth -= 1;
      if (depth === 0) return stripped.slice(open + 1, index);
    }
  }
  assert.fail(`unterminated Rust enum ${declaration}`);
}

function rustVariantNames(source, declaration) {
  const body = declarationBody(source, declaration);
  return [...body.matchAll(/^\s{4}([A-Z][A-Za-z0-9_]*)\s*(?=\{|,)/gm)].map(
    (match) => match[1],
  );
}

function rustEnumAttributeBlock(source, declaration) {
  const marker = new RegExp("^\\s*pub enum " + declaration + "\\s*\\{", "m");
  const match = marker.exec(source);
  assert.ok(match, "missing Rust enum " + declaration);
  const lines = source.slice(0, match.index).split(/\r?\n/);
  const attributes = [];
  while (lines.length > 0) {
    const line = lines.pop().trim();
    if (line === "" && attributes.length === 0) continue;
    if (/^(?:#\[[^\n]*\]|\/\/.*)$/.test(line)) {
      attributes.unshift(line);
      continue;
    }
    break;
  }
  assert.ok(attributes.length > 0, declaration + " has no contiguous attribute block");
  return attributes.join("\n");
}

function snakeCase(name) {
  return name.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
}

function fixtureVariantNames() {
  const marker = "fn fixture_requests";
  const start = tauriClientSource.indexOf(marker);
  assert.notEqual(start, -1, "missing exhaustive Tauri request fixture");
  const end = tauriClientSource.indexOf("#[test]", start);
  const fixture = tauriClientSource.slice(start, end === -1 ? undefined : end);
  return [...fixture.matchAll(/\bRequest::([A-Z][A-Za-z0-9_]*)\b/g)].map(
    (match) => match[1],
  );
}

function fixtureWireTagNames() {
  const marker = "fn every_current_request_variant_has_exact_wire_tag";
  const start = tauriClientSource.indexOf(marker);
  assert.notEqual(start, -1, "missing Tauri wire-tag fixture");
  const listStart = tauriClientSource.indexOf("let expected = [", start);
  const listEnd = tauriClientSource.indexOf("];", listStart);
  assert.notEqual(listStart, -1, "Tauri wire-tag fixture has no expected list");
  assert.notEqual(listEnd, -1, "Tauri wire-tag fixture list is unterminated");
  return [...tauriClientSource.slice(listStart, listEnd).matchAll(/"([a-z][a-z0-9_]*)"/g)].map(
    (match) => match[1],
  );
}

function balancedObject(source, open) {
  let depth = 0;
  let quote = false;
  for (let index = open; index < source.length; index += 1) {
    const current = source[index];
    if (quote) {
      if (current === "\\") index += 1;
      else if (current === '"') quote = false;
      continue;
    }
    if (current === '"') quote = true;
    else if (current === "{") depth += 1;
    else if (current === "}") {
      depth -= 1;
      if (depth === 0) return source.slice(open, index + 1);
    }
  }
  assert.fail("unterminated frontend invoke payload");
}

function frontendInvokeSites(source) {
  const sites = [];
  const invoke = /invoke\(\s*"([^"]+)"/g;
  for (const match of source.matchAll(invoke)) {
    let cursor = match.index + match[0].length;
    while (/\s/.test(source[cursor] ?? "")) cursor += 1;
    let payload = null;
    if (source[cursor] === ",") {
      cursor += 1;
      while (/\s/.test(source[cursor] ?? "")) cursor += 1;
      if (source[cursor] === "{") payload = balancedObject(source, cursor);
    }
    sites.push({ operation: match[1], payload });
  }
  return sites;
}

function payloadKeys(payload) {
  if (!payload) return [];
  const keys = [];
  let depth = 0;
  let quote = false;
  for (let index = 1; index < payload.length - 1; index += 1) {
    const current = payload[index];
    if (quote) {
      if (current === "\\") index += 1;
      else if (current === '"') quote = false;
      continue;
    }
    if (current === '"') {
      quote = true;
      continue;
    }
    if (current === "{") {
      depth += 1;
      continue;
    }
    if (current === "}") {
      depth -= 1;
      continue;
    }
    if (depth !== 0 || !/[A-Za-z_$]/.test(current)) continue;
    const identifier = payload.slice(index).match(/^[A-Za-z_$][A-Za-z0-9_$]*/)?.[0];
    if (!identifier) continue;
    let cursor = index + identifier.length;
    while (/\s/.test(payload[cursor] ?? "")) cursor += 1;
    if (payload[cursor] === ":") {
      keys.push(identifier);
      let valueDepth = 0;
      let valueQuote = false;
      let valueEnd = cursor;
      for (let value = cursor + 1; value < payload.length; value += 1) {
        const character = payload[value];
        if (valueQuote) {
          if (character === "\\") value += 1;
          else if (character === '"') valueQuote = false;
          continue;
        }
        if (character === '"') valueQuote = true;
        else if ("([{".includes(character)) valueDepth += 1;
        else if ((character === "," || character === "}") && valueDepth === 0) {
          valueEnd = value - 1;
          break;
        }
        else if (")]}".includes(character)) valueDepth -= 1;
      }
      index = valueEnd;
    } else if (payload[cursor] === "," || payload[cursor] === "}") {
      keys.push(identifier);
      index = cursor - 1;
    }
  }
  return keys;
}

const expectedFrontendPayloads = {
  mesh_status: [],
  mesh_identity: [],
  mesh_identity_set_label: ["label"],
  mesh_networks: [],
  mesh_peers: ["network"],
  mesh_roster_list: ["network"],
  mesh_topology_set: ["network", "topology", "hub"],
  mesh_network_id_generate: [],
  mesh_network_id_normalize: ["input"],
  mesh_config_show: [],
  mesh_network_add: ["config"],
  mesh_network_remove: ["network"],
  mesh_forget_all_networks: [],
  restart_app: [],
  mesh_factory_reset: [],
  mesh_network_update: ["config"],
  mesh_network_export_file: ["path", "config"],
  mesh_governance_propose_role_grant: ["network", "target", "role", "mfa_code"],
  mesh_governance_propose_role_revoke: ["network", "target", "mfa_code"],
  mesh_governance_propose_evict: ["network", "target", "mfa_code"],
  mesh_governance_mfa_prepare: ["network"],
  mesh_governance_mfa_query: ["network", "transaction_id"],
  mesh_governance_mfa_redeliver: ["network", "transaction_id"],
  mesh_governance_mfa_commit: ["network", "transaction_id"],
  mesh_governance_mfa_abort: ["network", "transaction_id"],
  mesh_governance_mfa_status: ["network"],
  mesh_governance_mfa_disable: ["network", "code"],
  update_status: [],
  update_check: [],
  update_apply: [],
  update_set_prefs: ["prefs"],
  mesh_services_status: [],
  mesh_services_set: ["services"],
  mesh_subscription_state: [],
};

function methodBody(name) {
  const marker = `  async function ${name}(`;
  const start = clientSource.indexOf(marker);
  assert.notEqual(start, -1, `missing production method ${name}`);
  const next = clientSource.indexOf("\n  async function ", start + marker.length);
  return clientSource.slice(start, next === -1 ? clientSource.length : next);
}

function invokePayload(body, operation) {
  const marker = `invoke("${operation}"`;
  const start = body.indexOf(marker);
  assert.notEqual(start, -1, `missing invoke(${operation})`);
  const payloadStart = body.indexOf("{", start + marker.length);
  const payloadEnd = body.indexOf("})", payloadStart);
  assert.notEqual(payloadStart, -1, `${operation} has no object payload`);
  assert.notEqual(payloadEnd, -1, `${operation} payload is not closed`);
  return body.slice(payloadStart, payloadEnd + 1);
}

test("network add/update serialize the canonical config envelope", () => {
  for (const method of ["networkAdd", "networkUpdate"]) {
    const payload = invokePayload(methodBody(method), `mesh_network_${method === "networkAdd" ? "add" : "update"}`);
    assert.match(payload, /\bconfig\b/);
    assert.doesNotMatch(payload, /\b(network|networkId|config_id)\s*:/);
  }
});

test("network removal serializes only the exact network identity", () => {
  const payload = invokePayload(methodBody("networkRemove"), "mesh_network_remove");
  assert.match(payload, /^\{\s*network\s*\}$/s);
  assert.doesNotMatch(payload, /purge|config|networkId/);
});

test("role governance serializes snake_case MFA and identity fields", () => {
  const contracts = [
    ["governanceProposeRoleGrant", "mesh_governance_propose_role_grant", "role"],
    ["governanceProposeRoleRevoke", "mesh_governance_propose_role_revoke", null],
    ["governanceProposeEvict", "mesh_governance_propose_evict", null],
  ];
  for (const [method, operation, role] of contracts) {
    const payload = invokePayload(methodBody(method), operation);
    assert.match(payload, /\bnetwork\b/);
    assert.match(payload, /\btarget\b/);
    if (role) assert.match(payload, /\brole\b/);
    assert.match(payload, /\bmfa_code\s*:/);
    assert.doesNotMatch(payload, /\bmfaCode\b/);
  }
});

test("MFA transaction operations serialize the exact transaction_id", () => {
  const contracts = ["Query", "Redeliver", "Commit", "Abort"];
  for (const suffix of contracts) {
    const payload = invokePayload(
      methodBody(`governanceMfa${suffix}`),
      `mesh_governance_mfa_${suffix.toLowerCase()}`,
    );
    assert.match(payload, /\bnetwork\b/);
    assert.match(payload, /\btransaction_id\s*:/);
    assert.doesNotMatch(payload, /\btransactionId\b/);
  }
});

test("daemon and Tauri Request enums have exhaustive exact wire coverage", () => {
  const daemonVariants = rustVariantNames(daemonWireSource, "Request");
  const tauriVariants = rustVariantNames(tauriClientSource, "Request");
  const expected = [...expectedRequestVariants].sort();

  assert.equal(expected.length, 62);
  assert.deepEqual([...new Set(daemonVariants)].sort(), expected);
  assert.deepEqual([...new Set(tauriVariants)].sort(), expected);
  assert.equal(daemonVariants.length, 62, "daemon Request has duplicate/missing variants");
  assert.equal(tauriVariants.length, 62, "Tauri Request has duplicate/missing variants");

  const fixtureVariants = fixtureVariantNames();
  assert.equal(fixtureVariants.length, 62, "Tauri fixture must cover every variant once");
  assert.deepEqual([...new Set(fixtureVariants)].sort(), expected);

  for (const source of [daemonWireSource, tauriClientSource]) {
    const requestAttributes = rustEnumAttributeBlock(source, "Request");
    assert.match(requestAttributes, /serde\s*\(tag\s*=\s*"op"/);
    assert.match(requestAttributes, /rename_all\s*=\s*"snake_case"/);

    // Negative control: removing the bound serde line must not let a
    // detached/later attribute satisfy the exact-enum binding check.
    const serdeLine =
      /^[ \t]*#\[serde\s*\(\s*tag\s*=\s*"op"\s*,\s*rename_all\s*=\s*"snake_case"\s*\)\][ \t]*(?:\r?\n|$)/m;
    const removeBoundSerdeLine = (candidate) => {
      const detached = candidate.replace(serdeLine, "");
      assert.notEqual(
        detached,
        candidate,
        "expected the Request-bound serde line to be removed",
      );
      return detached;
    };
    const detachedSources = [
      removeBoundSerdeLine(source),
      removeBoundSerdeLine(source.replace(/\r?\n/g, "\r\n")),
    ];
    for (const detachedSource of detachedSources) {
      const detachedAttributes = rustEnumAttributeBlock(detachedSource, "Request");
      assert.doesNotMatch(
        detachedAttributes,
        /serde\s*\(tag\s*=\s*"op"/,
        "detached serde metadata must not satisfy Request binding",
      );
    }
  }

  const wireNames = expectedRequestVariants.map(snakeCase);
  assert.equal(new Set(wireNames).size, 62, "wire operation names must remain unique");
  assert.deepEqual(
    fixtureWireTagNames().sort(),
    wireNames.sort(),
    "Tauri serialization tags drifted",
  );
});

test("member relay requests are absent from both current wire facades", () => {
  for (const source of [daemonWireSource, tauriClientSource]) {
    const variants = rustVariantNames(source, "Request");
    const body = declarationBody(source, "Request");
    for (const suffix of ["Open", "Accept", "Send", "Recv", "Close", "State"]) {
      const retired = `ClosedRelay${suffix}`;
      assert.ok(!variants.includes(retired), `${retired} must not be constructible`);
      assert.ok(
        !body.includes(`"${snakeCase(retired)}"`),
        `${retired} must not survive as a renamed or aliased wire operation`,
      );
    }
  }
});

test("every frontend invoke uses the exact payload keys for its Tauri command", () => {
  const sites = [
    ...frontendInvokeSites(clientSource),
    ...frontendInvokeSites(networkSettingsSource),
  ];
  const expectedOperations = Object.keys(expectedFrontendPayloads).sort();
  const actualOperations = [...new Set(sites.map((site) => site.operation))].sort();
  assert.deepEqual(actualOperations, expectedOperations);

  for (const site of sites) {
    assert.deepEqual(
      payloadKeys(site.payload),
      expectedFrontendPayloads[site.operation],
      `${site.operation} payload drifted from its exact Tauri boundary`,
    );
    assert.doesNotMatch(
      site.payload ?? "",
      /\b(?:mfaCode|transactionId|networkId|configId)\s*:/,
    );
  }
});
