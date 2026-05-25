<script lang="ts">
  /** Status tab in the per-network overlay. At-a-glance summary:
   *  network kind, topology, peer count, your role, transition log. */
  import { meshClient } from "../../mesh-client.svelte";
  import { governance } from "../../network-governance.svelte";
  import {
    networkDisplayName,
    topologyName,
    topologyHub,
    type NetworkSummary,
  } from "../../types";
  import NetworkKindBadge from "./NetworkKindBadge.svelte";
  import RoleChip from "./RoleChip.svelte";

  const {
    network,
  }: {
    network: NetworkSummary;
  } = $props();

  const govView = $derived(governance.stateFor(network.config_id));
  const kind = $derived(govView.kind);
  const peers = $derived(meshClient.peersByNetwork[network.config_id] ?? []);
  const selfPubkey = $derived(meshClient.identity?.pubkey ?? null);
  const myRole = $derived(governance.localRole(network.config_id, selfPubkey));
  const transitions = $derived([...govView.transitions].reverse());

  function fmtRelative(ms: number): string {
    const diff = Date.now() - ms;
    if (diff < 60_000) return "just now";
    if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
    if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
    return new Date(ms).toLocaleDateString();
  }

  function transitionSummary(t: (typeof transitions)[number]): string {
    const v = t.variant;
    switch (v.kind) {
      case "kind_change":
        return `→ ${v.to}`;
      case "role_grant":
        return `granted ${v.to} to ${v.target.slice(0, 8)}…`;
      case "role_revoke":
        return `revoked role from ${v.target.slice(0, 8)}…`;
      case "split":
        return `split → ${v.new_network_id.slice(0, 10)}…`;
    }
  }
</script>

<div class="tab">
  <div class="card">
    <div class="card-head">
      <div class="title">
        <NetworkKindBadge {kind} size={16} />
        <span>{networkDisplayName(network)}</span>
      </div>
      <div class="kind-pill" data-kind={kind}>
        {kind === "closed" ? "Closed" : "Open"}
      </div>
    </div>

    <dl class="grid">
      <dt>Network ID</dt>
      <dd class="mono break">{network.network_id}</dd>

      <dt>Phase</dt>
      <dd>
        <span class="phase" data-phase={network.phase}>
          {network.phase.replace("_", " ")}
        </span>
      </dd>

      <dt>Topology</dt>
      <dd>
        {topologyName(network.topology)}
        {#if topologyName(network.topology) === "star"}
          · hub <span class="mono">{topologyHub(network.topology)}</span>
        {/if}
      </dd>

      <dt>Peers</dt>
      <dd>{peers.length} tracked</dd>

      {#if kind === "closed"}
        <dt>Your role</dt>
        <dd>
          <RoleChip role={myRole} size="md" />
        </dd>
      {/if}
    </dl>
  </div>

  {#if govView.splits.length > 0}
    <div class="card">
      <div class="card-title">Splits spawned from this network</div>
      <ul class="splits">
        {#each govView.splits as s}
          <li>
            <code class="mono">{s.new_network_id.slice(0, 18)}…</code>
            <span class="muted">
              {s.members.length} members · {fmtRelative(s.spawned_at)}
              {#if selfPubkey && !s.members.includes(selfPubkey)}
                · you are <strong>not</strong> a member
              {/if}
            </span>
          </li>
        {/each}
      </ul>
    </div>
  {/if}

  {#if transitions.length > 0}
    <div class="card">
      <div class="card-title">Transition log</div>
      <ol class="transitions">
        {#each transitions as t}
          <li>
            <span class="t-time">{fmtRelative(t.at)}</span>
            <span class="t-summary">{transitionSummary(t)}</span>
            <span class="t-signers">{t.signers.length} signer{t.signers.length === 1 ? "" : "s"}</span>
          </li>
        {/each}
      </ol>
    </div>
  {/if}
</div>

<style>
  .tab {
    display: flex;
    flex-direction: column;
    gap: 0.85rem;
  }
  .card {
    background: #131318;
    border: 1px solid #1e1e25;
    border-radius: 8px;
    padding: 0.85rem 1rem;
  }
  .card-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.6rem;
    margin-bottom: 0.75rem;
  }
  .title {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    font-weight: 600;
    font-size: 0.95rem;
  }
  .kind-pill {
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    padding: 0.12rem 0.55rem;
    border-radius: 999px;
    background: #161618;
    border: 1px solid #222226;
    color: #94a3b8;
  }
  .kind-pill[data-kind="closed"] {
    color: #fbbf24;
    background: #2a200c;
    border-color: #4a3a14;
  }
  .card-title {
    font-weight: 600;
    font-size: 0.85rem;
    margin-bottom: 0.6rem;
    color: #ccc;
  }
  .grid {
    display: grid;
    grid-template-columns: 8rem 1fr;
    gap: 0.55rem 0.85rem;
    font-size: 0.84rem;
  }
  .grid dt {
    color: #888;
  }
  .grid dd {
    color: #e0e0e0;
    display: flex;
    align-items: center;
    gap: 0.4rem;
    flex-wrap: wrap;
  }
  .mono {
    font-family: ui-monospace, SFMono-Regular, monospace;
    font-size: 0.78rem;
  }
  .break {
    word-break: break-all;
  }
  .phase {
    display: inline-block;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    padding: 0.1rem 0.5rem;
    border-radius: 999px;
    background: #161618;
    border: 1px solid #222226;
    color: #888;
  }
  .phase[data-phase="active"] {
    color: #b9f5cc;
    background: #112a1c;
    border-color: #1c4a30;
  }
  .phase[data-phase="degraded"] {
    color: #fbbf24;
    background: #2a200c;
    border-color: #4a3a14;
  }
  .phase[data-phase="stopped"] {
    color: #fca5a5;
    background: #2a1414;
    border-color: #4a2222;
  }
  .splits {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    font-size: 0.82rem;
  }
  .splits li {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
  }
  .muted {
    color: #888;
    font-size: 0.78rem;
  }
  .transitions {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    font-size: 0.8rem;
  }
  .transitions li {
    display: grid;
    grid-template-columns: 6rem 1fr auto;
    gap: 0.5rem;
    padding: 0.3rem 0;
    border-bottom: 1px solid #1a1a20;
  }
  .transitions li:last-child {
    border-bottom: none;
  }
  .t-time {
    color: #888;
    font-size: 0.74rem;
  }
  .t-summary {
    color: #e0e0e0;
  }
  .t-signers {
    color: #888;
    font-size: 0.74rem;
  }
</style>
