<script lang="ts">
  /** Read-only network status. Kind is config-owned and roles are projected
   *  from the daemon-owned roster; no governance snapshot is consumed. */
  import { meshClient } from "../../mesh-client.svelte";
  import { networkDisplayName, topologyName, topologyHub, type NetworkSummary } from "../../types";
  import NetworkKindBadge from "./NetworkKindBadge.svelte";
  import RoleChip from "./RoleChip.svelte";

  const { network }: { network: NetworkSummary } = $props();
  const kind = $derived(meshClient.networkKindsByNetwork[network.config_id] ?? "open");
  const peers = $derived(meshClient.peersByNetwork[network.config_id] ?? []);
  const selfId = $derived(meshClient.identity?.pubkey ?? null);
  const myRole = $derived(
    meshClient.rostersByNetwork[network.config_id]?.find((peer) => peer.device_id === selfId)?.role ?? "member",
  );
</script>

<div class="tab">
  <div class="card">
    <div class="card-head">
      <div class="title"><NetworkKindBadge {kind} size={16} /><span>{networkDisplayName(network)}</span></div>
      <div class="kind-pill" data-kind={kind}>{kind === "closed" ? "Closed" : "Open"}</div>
    </div>
    <dl class="grid">
      <dt>Network ID</dt><dd class="mono break">{network.network_id}</dd>
      <dt>Phase</dt><dd><span class="phase" data-phase={network.phase}>{network.phase.replace("_", " ")}</span></dd>
      <dt>Topology</dt><dd>{topologyName(network.topology).replace("_", " ")}{#if network.topology.kind === "star"} · hub <span class="mono">{topologyHub(network.topology)}</span>{/if}</dd>
      <dt>Peers</dt><dd>{peers.length} tracked</dd>
      {#if kind === "closed"}<dt>Your role</dt><dd><RoleChip role={myRole} size="md" /></dd>{/if}
    </dl>
  </div>
</div>

<style>
  .tab { display: flex; flex-direction: column; gap: .85rem; }
  .card { background: #131318; border: 1px solid #1e1e25; border-radius: 8px; padding: .85rem 1rem; }
  .card-head { display: flex; align-items: center; justify-content: space-between; gap: .6rem; margin-bottom: .75rem; }
  .title { display: flex; align-items: center; gap: .4rem; font-weight: 600; font-size: .95rem; }
  .kind-pill { font-size: .65rem; text-transform: uppercase; letter-spacing: .06em; padding: .12rem .55rem; border-radius: 999px; background: #161618; border: 1px solid #222226; color: #94a3b8; }
  .kind-pill[data-kind="closed"] { color: #fbbf24; background: #2a200c; border-color: #4a3a14; }
  .grid { display: grid; grid-template-columns: 8rem 1fr; gap: .55rem .85rem; font-size: .84rem; }
  .grid dt { color: #888; } .grid dd { margin: 0; color: #d0d0d0; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .break { overflow-wrap: anywhere; } .phase { color: #93c5fd; }
</style>
