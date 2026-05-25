<script lang="ts">
  import { meshClient } from "../mesh-client.svelte";
  import { networkDisplayName, topologyName } from "../types";
  import type { NetworkSummary, PeerInfo } from "../types";
  import { governance } from "../network-governance.svelte";
  import NetworkKindBadge from "./network/NetworkKindBadge.svelte";

  const {
    focusedConfigId,
    selectedPeerId,
    onSelectNetwork,
    onSelectPeer,
    onOpenNetworksSettings,
    onOpenNetworkOverlay,
  }: {
    focusedConfigId: string | null;
    selectedPeerId: string | null;
    onSelectNetwork: (configId: string) => void;
    onSelectPeer: (deviceId: string) => void;
    onOpenNetworksSettings: () => void;
    /** Open the per-network settings/control overlay against a
     *  specific network. Triggered by the gear icon on each
     *  sidebar row. The overlay slides over the graph; the rest
     *  of the layout stays intact. */
    onOpenNetworkOverlay: (configId: string) => void;
  } = $props();

  // The user can independently expand/collapse each network's
  // member list. Networks default to expanded; the focused one is
  // forced open so the user can see the peers they're currently
  // visualising.
  let collapsedNetworks = $state<Set<string>>(new Set());

  function toggleNetwork(configId: string) {
    const next = new Set(collapsedNetworks);
    if (next.has(configId)) next.delete(configId);
    else next.add(configId);
    collapsedNetworks = next;
  }

  function isExpanded(net: NetworkSummary): boolean {
    if (net.config_id === focusedConfigId) return true;
    return !collapsedNetworks.has(net.config_id);
  }

  function peerStatusColor(p: PeerInfo): string {
    if (p.status === "active" && !p.local_shelved && !p.remote_shelved)
      return "#4ade80";
    if (p.status === "active") return "#facc15";
    if (p.status === "shelved") return "#facc15";
    if (p.status === "pending_approval") return "#a78bfa";
    if (p.status === "handshaking") return "#60a5fa";
    if (p.status === "sighted") return "#94a3b8";
    if (p.status === "reconnecting") return "#fb923c";
    if (p.status === "offline") return "#6b7280";
    if (p.status === "error") return "#ef4444";
    return "#888";
  }

  function statusText(p: PeerInfo): string {
    if (p.status === "active" && (p.local_shelved || p.remote_shelved))
      return "shelved";
    return p.status.replace("_", " ");
  }

  function shortId(id: string): string {
    if (id.length <= 12) return id;
    return id.slice(0, 6) + "…" + id.slice(-4);
  }

  function phaseLabel(net: NetworkSummary): string {
    return net.phase.replace("_", " ");
  }
</script>

<aside class="sidebar">
  <div class="header">
    <span>Networks</span>
    <button
      class="add"
      onclick={onOpenNetworksSettings}
      title="Open Networks settings"
      aria-label="Networks settings"
    >
      <svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true">
        <path
          fill="none"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
          d="M12 5v14M5 12h14"
        />
      </svg>
    </button>
  </div>

  <div class="list">
    {#if meshClient.networks.length === 0}
      <div class="empty">
        No networks joined.
        <button class="link" onclick={onOpenNetworksSettings}>Configure</button>
      </div>
    {:else}
      {#each meshClient.networks as net (net.config_id)}
        {@const peers = meshClient.peersByNetwork[net.config_id] ?? []}
        {@const expanded = isExpanded(net)}
        {@const isFocused = net.config_id === focusedConfigId}
        {@const kind = governance.stateFor(net.config_id).kind}
        {@const pendingProposals = governance.stateFor(net.config_id).pending.length}
        <div class="net" class:focused={isFocused}>
          <div class="net-row-wrap">
            <button
              class="net-row"
              onclick={() => {
                if (isFocused) toggleNetwork(net.config_id);
                else onSelectNetwork(net.config_id);
              }}
            >
              <span class="caret" class:open={expanded}>
                <svg viewBox="0 0 24 24" width="10" height="10" aria-hidden="true">
                  <path fill="currentColor" d="M8 6l8 6-8 6z" />
                </svg>
              </span>
              <NetworkKindBadge {kind} size={11} />
              <span
                class="net-name"
                title="Network ID: {net.network_id}&#10;Local config id: {net.config_id}&#10;Kind: {kind}"
              >
                {networkDisplayName(net)}
              </span>
              <span class="net-phase" data-phase={net.phase}>{phaseLabel(net)}</span>
            </button>
            <button
              class="gear"
              onclick={(e) => {
                e.stopPropagation();
                onOpenNetworkOverlay(net.config_id);
              }}
              title="Settings & roster for {networkDisplayName(net)}"
              aria-label="Open network settings"
            >
              {#if pendingProposals > 0}
                <span class="gear-badge" aria-hidden="true"></span>
              {/if}
              <svg viewBox="0 0 24 24" width="13" height="13" aria-hidden="true">
                <path
                  fill="currentColor"
                  d="M19.43 12.98a7.95 7.95 0 0 0 0-1.96l2.11-1.65a.5.5 0 0 0 .12-.64l-2-3.46a.5.5 0 0 0-.61-.22l-2.49 1a8.07 8.07 0 0 0-1.69-.98l-.38-2.65A.5.5 0 0 0 14 2h-4a.5.5 0 0 0-.49.42l-.38 2.65a8.07 8.07 0 0 0-1.69.98l-2.49-1a.5.5 0 0 0-.61.22l-2 3.46a.5.5 0 0 0 .12.64l2.11 1.65c-.05.32-.08.65-.08.98s.03.66.08.98L2.46 14.6a.5.5 0 0 0-.12.64l2 3.46a.5.5 0 0 0 .61.22l2.49-1a8.07 8.07 0 0 0 1.69.98l.38 2.65c.05.24.25.42.49.42h4c.24 0 .44-.18.49-.42l.38-2.65a8.07 8.07 0 0 0 1.69-.98l2.49 1a.5.5 0 0 0 .61-.22l2-3.46a.5.5 0 0 0-.12-.64l-2.11-1.65zM12 15.5A3.5 3.5 0 1 1 12 8.5a3.5 3.5 0 0 1 0 7z"
                />
              </svg>
            </button>
          </div>
          {#if expanded}
            <div class="members">
              <div class="member self">
                <span class="dot" style="background:#6e6ef7"></span>
                <span class="member-name">this device</span>
                <span class="topo-tag">{topologyName(net.topology)}</span>
              </div>
              {#if peers.length === 0}
                <div class="member-empty">no peers</div>
              {:else}
                {#each peers as peer (peer.device_id)}
                  <button
                    class="member"
                    class:selected={selectedPeerId === peer.device_id}
                    onclick={() => {
                      if (!isFocused) onSelectNetwork(net.config_id);
                      onSelectPeer(peer.device_id);
                    }}
                    title={peer.device_id}
                  >
                    <span
                      class="dot"
                      style="background:{peerStatusColor(peer)}"
                    ></span>
                    <span class="member-name">
                      {peer.label || shortId(peer.device_id)}
                    </span>
                    <span class="member-status">{statusText(peer)}</span>
                  </button>
                {/each}
              {/if}
            </div>
          {/if}
        </div>
      {/each}
    {/if}
  </div>
</aside>

<style>
  .sidebar {
    width: 240px;
    background: #0d0d0d;
    border-right: 1px solid #1e1e1e;
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
    min-height: 0;
  }
  .header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.6rem 0.85rem;
    border-bottom: 1px solid #1e1e1e;
    flex-shrink: 0;
    font-size: 0.72rem;
    color: #888;
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }
  .add {
    background: none;
    border: none;
    color: #888;
    cursor: pointer;
    padding: 0.2rem;
    border-radius: 4px;
    display: inline-flex;
    align-items: center;
    line-height: 0;
  }
  .add:hover {
    background: #1a1a1a;
    color: #e8e8e8;
  }
  .list {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 0.35rem 0;
  }
  .empty {
    color: #666;
    font-size: 0.8rem;
    padding: 1rem 0.85rem;
    line-height: 1.5;
  }
  .link {
    background: none;
    border: none;
    color: #6e6ef7;
    cursor: pointer;
    font-size: 0.8rem;
    padding: 0;
    text-decoration: underline;
  }
  .net {
    display: flex;
    flex-direction: column;
  }
  .net.focused .net-name {
    color: #e8e8e8;
  }
  .net-row-wrap {
    display: flex;
    align-items: stretch;
    position: relative;
  }
  .net-row-wrap:hover .gear {
    color: #ccc;
    background: #131318;
  }
  .net.focused .net-row-wrap {
    background: #1a1a2a;
    border-left: 2px solid #6e6ef7;
  }
  .net-row {
    flex: 1;
    min-width: 0;
    display: flex;
    align-items: center;
    gap: 0.45rem;
    background: none;
    border: none;
    color: #aaa;
    cursor: pointer;
    text-align: left;
    padding: 0.4rem 0.85rem;
    font: inherit;
    font-size: 0.83rem;
  }
  .net.focused .net-row {
    padding-left: calc(0.85rem - 2px);
  }
  .net-row:hover {
    background: #131318;
    color: #e8e8e8;
  }
  .gear {
    position: relative;
    background: none;
    border: none;
    color: #555;
    cursor: pointer;
    padding: 0 0.55rem;
    display: flex;
    align-items: center;
    line-height: 0;
    transition:
      color 0.12s,
      background 0.12s;
  }
  .gear:hover {
    color: #b8b8ff !important;
    background: #1a1a2a !important;
  }
  .gear-badge {
    position: absolute;
    top: 0.4rem;
    right: 0.3rem;
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: #fbbf24;
    box-shadow: 0 0 0 2px #0d0d0d;
  }
  .caret {
    color: #666;
    display: inline-flex;
    align-items: center;
    transition: transform 0.15s ease;
  }
  .caret.open {
    transform: rotate(90deg);
  }
  .net-name {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .net-phase {
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: #6b7280;
    padding: 0.05rem 0.4rem;
    border-radius: 999px;
    background: #161618;
    border: 1px solid #222226;
  }
  .net-phase[data-phase="active"] {
    color: #b9f5cc;
    background: #112a1c;
    border-color: #1c4a30;
  }
  .net-phase[data-phase="degraded"] {
    color: #fbbf24;
    background: #2a200c;
    border-color: #4a3a14;
  }
  .net-phase[data-phase="stopped"] {
    color: #fca5a5;
    background: #2a1414;
    border-color: #4a2222;
  }
  .members {
    display: flex;
    flex-direction: column;
    padding: 0.15rem 0 0.4rem 1.6rem;
    gap: 0.05rem;
  }
  .member {
    display: flex;
    align-items: center;
    gap: 0.45rem;
    background: none;
    border: none;
    color: #999;
    cursor: pointer;
    text-align: left;
    padding: 0.25rem 0.75rem 0.25rem 0.5rem;
    font: inherit;
    font-size: 0.78rem;
    border-radius: 4px;
    border-left: 2px solid transparent;
  }
  .member:hover {
    background: #131318;
    color: #e8e8e8;
  }
  .member.selected {
    background: #1a1a2a;
    color: #e8e8e8;
    border-left-color: #6e6ef7;
  }
  .member.self {
    color: #b8b8ff;
    cursor: default;
    padding-top: 0.25rem;
    padding-bottom: 0.25rem;
  }
  .member.self:hover {
    background: none;
  }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
  }
  .member-name {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .member-status {
    font-size: 0.62rem;
    color: #666;
    text-transform: lowercase;
  }
  .topo-tag {
    font-size: 0.6rem;
    color: #888;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    background: #131318;
    border: 1px solid #1e1e25;
    padding: 0.02rem 0.35rem;
    border-radius: 3px;
  }
  .member-empty {
    color: #555;
    font-size: 0.75rem;
    padding: 0.2rem 0.5rem;
    font-style: italic;
  }
</style>
