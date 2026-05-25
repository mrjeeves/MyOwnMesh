<script lang="ts">
  /** Per-network settings/control overlay. Opened from the gear
   *  icon on each network row in the sidebar — slides over the
   *  graph as a side-panel (not full-window) so the node-map stays
   *  partially visible behind it.
   *
   *  Four tabs:
   *    Status      — overview: kind, topology, role, transitions
   *    Settings    — edit label/topology/relays/STUN/TURN/auto-approve
   *    Roster      — approved devices + role assignment
   *    Governance  — open/closed kind toggle + propose/sign/deny/split */

  import { meshClient } from "../../mesh-client.svelte";
  import { networkDisplayName, type NetworkSummary } from "../../types";
  import { governance } from "../../network-governance.svelte";
  import NetworkKindBadge from "./NetworkKindBadge.svelte";
  import NetworkOverlayStatus from "./NetworkOverlayStatus.svelte";
  import NetworkOverlaySettings from "./NetworkOverlaySettings.svelte";
  import NetworkOverlayRoster from "./NetworkOverlayRoster.svelte";
  import NetworkOverlayGovernance from "./NetworkOverlayGovernance.svelte";

  type Tab = "status" | "settings" | "roster" | "governance";

  const {
    configId,
    initialTab = "status",
    onClose,
  }: {
    configId: string;
    initialTab?: Tab;
    onClose: () => void;
  } = $props();

  // svelte-ignore state_referenced_locally
  let tab = $state<Tab>(initialTab);

  const network = $derived<NetworkSummary | null>(
    meshClient.networks.find((n) => n.config_id === configId) ?? null,
  );

  const govState = $derived(governance.stateFor(configId));
  const pendingCount = $derived(govState.pending.length);

  // Close on Escape — a common affordance for overlay panels.
  function onKeydown(e: KeyboardEvent) {
    if (e.key === "Escape") onClose();
  }
</script>

<svelte:window onkeydown={onKeydown} />

<div class="backdrop" onclick={onClose} role="presentation"></div>
<aside class="panel" aria-label="Network settings">
  <header class="head">
    {#if network}
      <div class="head-title">
        <NetworkKindBadge kind={govState.kind} size={16} />
        <h2>{networkDisplayName(network)}</h2>
        <code class="net-id" title="Wire-level network id">
          {network.network_id}
        </code>
      </div>
    {:else}
      <h2 class="missing">Network not found</h2>
    {/if}
    <button class="close" onclick={onClose} aria-label="Close" title="Close">
      ✕
    </button>
  </header>

  <nav class="tabs" aria-label="Network settings tabs">
    <button
      class="tab-btn"
      class:active={tab === "status"}
      onclick={() => (tab = "status")}
    >
      Status
    </button>
    <button
      class="tab-btn"
      class:active={tab === "settings"}
      onclick={() => (tab = "settings")}
    >
      Settings
    </button>
    <button
      class="tab-btn"
      class:active={tab === "roster"}
      onclick={() => (tab = "roster")}
    >
      Roster
    </button>
    <button
      class="tab-btn"
      class:active={tab === "governance"}
      onclick={() => (tab = "governance")}
    >
      Governance
      {#if pendingCount > 0}
        <span class="badge">{pendingCount}</span>
      {/if}
    </button>
  </nav>

  <div class="body">
    {#if network}
      {#key configId + ":" + tab}
        {#if tab === "status"}
          <NetworkOverlayStatus {network} />
        {:else if tab === "settings"}
          <NetworkOverlaySettings {network} />
        {:else if tab === "roster"}
          <NetworkOverlayRoster {network} />
        {:else if tab === "governance"}
          <NetworkOverlayGovernance {network} />
        {/if}
      {/key}
    {:else}
      <div class="empty">
        The network you were viewing has been removed from the
        daemon. Close this panel and pick a different network from
        the sidebar.
      </div>
    {/if}
  </div>
</aside>

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.45);
    z-index: 39;
    backdrop-filter: blur(1px);
  }
  .panel {
    position: fixed;
    top: 0;
    right: 0;
    bottom: 0;
    width: clamp(420px, 38vw, 640px);
    background: #0f0f14;
    border-left: 1px solid #1e1e25;
    box-shadow: -8px 0 24px rgba(0, 0, 0, 0.4);
    z-index: 40;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .head {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.7rem 1rem;
    border-bottom: 1px solid #1e1e25;
    flex-shrink: 0;
  }
  .head-title {
    flex: 1;
    min-width: 0;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  h2 {
    font-size: 0.95rem;
    font-weight: 600;
    margin: 0;
    color: #e8e8e8;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  h2.missing {
    color: #888;
    font-weight: 500;
  }
  .net-id {
    font-family: ui-monospace, SFMono-Regular, monospace;
    color: #666;
    font-size: 0.72rem;
    background: #131318;
    border: 1px solid #1e1e25;
    padding: 0.08rem 0.4rem;
    border-radius: 3px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 12rem;
  }
  .close {
    background: none;
    border: none;
    color: #888;
    cursor: pointer;
    padding: 0.3rem 0.5rem;
    border-radius: 4px;
    font-size: 1rem;
    line-height: 1;
  }
  .close:hover {
    background: #1a1a22;
    color: #e8e8e8;
  }
  .tabs {
    display: flex;
    border-bottom: 1px solid #1e1e25;
    padding: 0 0.5rem;
    flex-shrink: 0;
  }
  .tab-btn {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.6rem 0.85rem;
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    color: #888;
    cursor: pointer;
    font: inherit;
    font-size: 0.82rem;
  }
  .tab-btn:hover:not(.active) {
    color: #ccc;
  }
  .tab-btn.active {
    color: #e8e8e8;
    border-bottom-color: #6e6ef7;
  }
  .badge {
    font-size: 0.62rem;
    background: #2a200c;
    color: #fbbf24;
    border: 1px solid #4a3a14;
    padding: 0.05rem 0.4rem;
    border-radius: 999px;
    line-height: 1;
  }
  .body {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 1rem;
  }
  .empty {
    color: #888;
    font-size: 0.84rem;
    line-height: 1.55;
    padding: 1rem;
    text-align: center;
    background: #131318;
    border: 1px solid #1e1e25;
    border-radius: 6px;
  }
</style>
