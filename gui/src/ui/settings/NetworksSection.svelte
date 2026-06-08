<script lang="ts">
  /** Settings → Networks. The single home for everything about a saved
   *  network. A picker chooses which network the sub-tabs operate on:
   *
   *    Status      — read-only overview (kind, topology, role, log)
   *    Settings    — edit label / topology / signaling / STUN / TURN /
   *                  auto-approve, export, and remove
   *    Connections — live per-peer table (connections only; pending
   *                  approvals live in the top-level Approvals tab)
   *    Roster      — approved devices + role assignment + pre-authorise
   *    Governance  — open/closed kind + propose / sign / deny / split
   *
   *  Status / Settings / Roster / Governance reuse the per-network panels
   *  that used to live in a floating overlay over the graph — that
   *  overlay is gone; its features and clarity are folded in here so
   *  there's one obvious place to manage a network. */

  import { meshClient } from "../../mesh-client.svelte";
  import { networkDisplayName } from "../../types";
  import type { NetworkSummary, PeerInfo } from "../../types";
  import AddNetworkModal from "./AddNetworkModal.svelte";
  import NetworkStatusPanel from "../network/NetworkStatusPanel.svelte";
  import NetworkSettingsPanel from "../network/NetworkSettingsPanel.svelte";
  import NetworkRosterPanel from "../network/NetworkRosterPanel.svelte";
  import NetworkGovernancePanel from "../network/NetworkGovernancePanel.svelte";
  import { governance } from "../../network-governance.svelte";

  const {
    focusedConfigId,
  }: {
    focusedConfigId: string | null;
  } = $props();

  let showAddModal = $state(false);

  type SubTab = "status" | "settings" | "connections" | "roster" | "governance";

  // svelte-ignore state_referenced_locally
  let tab = $state<SubTab>("status");

  /** Which saved network the sub-tabs operate on. Defaults to whatever
   *  the graph is focused on (so the sidebar gear lands here on the right
   *  network); the user can switch via the picker. */
  // svelte-ignore state_referenced_locally
  let selectedConfigId = $state<string | null>(focusedConfigId);
  // svelte-ignore state_referenced_locally
  let lastFocused = $state<string | null>(focusedConfigId);

  $effect(() => {
    // Follow the parent's focus: when it re-focuses a network (e.g. the
    // sidebar gear opens us against a specific one) switch the picker to
    // it, but otherwise leave the user's manual selection alone.
    if (focusedConfigId && focusedConfigId !== lastFocused) {
      lastFocused = focusedConfigId;
      if (meshClient.networks.some((n) => n.config_id === focusedConfigId)) {
        selectedConfigId = focusedConfigId;
      }
    }
    if (!selectedConfigId && meshClient.networks.length > 0) {
      selectedConfigId = meshClient.networks[0].config_id;
    }
    if (
      selectedConfigId &&
      !meshClient.networks.some((n) => n.config_id === selectedConfigId)
    ) {
      selectedConfigId = meshClient.networks[0]?.config_id ?? null;
    }
  });

  const selected = $derived<NetworkSummary | null>(
    selectedConfigId
      ? meshClient.networks.find((n) => n.config_id === selectedConfigId) ?? null
      : null,
  );

  const peers = $derived<PeerInfo[]>(
    selected ? meshClient.peersByNetwork[selected.config_id] ?? [] : [],
  );

  const pendingProposals = $derived(
    selected ? governance.stateFor(selected.config_id).pending.length : 0,
  );

  function shortId(id: string): string {
    if (id.length <= 16) return id;
    return id.slice(0, 8) + "…" + id.slice(-6);
  }
</script>

<div class="section">
  <div class="h-tabs">
    <button class:active={tab === "status"} onclick={() => (tab = "status")}>
      Status
    </button>
    <button class:active={tab === "settings"} onclick={() => (tab = "settings")}>
      Settings
    </button>
    <button
      class:active={tab === "connections"}
      onclick={() => (tab = "connections")}
    >
      Connections
    </button>
    <button class:active={tab === "roster"} onclick={() => (tab = "roster")}>
      Roster
    </button>
    <button
      class="gov-tab"
      class:active={tab === "governance"}
      onclick={() => (tab = "governance")}
    >
      Governance
      {#if pendingProposals > 0}
        <span class="badge">{pendingProposals}</span>
      {/if}
    </button>
  </div>

  <div class="content">
    {#if meshClient.networks.length === 0}
      <div class="placeholder">
        <p>No networks joined yet.</p>
        <button class="primary" onclick={() => (showAddModal = true)}>
          + Add network
        </button>
        <p class="hint">
          Networks are saved to <code>~/.myownmesh/config.json</code> as plain
          JSON. The add dialog can also import from a file or paste, and you
          can export any existing network back to JSON from the Settings tab.
        </p>
      </div>
    {:else}
      <div class="picker">
        <label for="net-picker">Network</label>
        <select id="net-picker" bind:value={selectedConfigId}>
          {#each meshClient.networks as n}
            <option value={n.config_id}>{networkDisplayName(n)}</option>
          {/each}
        </select>
        <button class="add" onclick={() => (showAddModal = true)}>
          + Add network
        </button>
      </div>

      {#if selected}
        {#key selected.config_id}
          {#if tab === "status"}
            <NetworkStatusPanel network={selected} />
          {:else if tab === "settings"}
            <NetworkSettingsPanel network={selected} />
          {:else if tab === "connections"}
            <div class="card">
              <!-- Connections is for connections only — every row here
                   represents a peer the engine is actively tracking.
                   Pending approvals are handled in the top-level
                   Approvals tab so the "how do I add a device?" surface
                   stays distinct from "what's connected right now?".
                   Connection peers that aren't yet approved still appear
                   here (with their pending status) so the user can
                   confirm the engine has sighted them. -->
              {#if peers.length === 0}
                <div class="empty">No peers yet — waiting for sightings.</div>
              {:else}
                <table class="peers">
                  <thead>
                    <tr>
                      <th>Peer</th>
                      <th>Status</th>
                      <th>Auth</th>
                      <th>RTT</th>
                      <th>Shelved</th>
                    </tr>
                  </thead>
                  <tbody>
                    {#each peers as p (p.device_id)}
                      <tr>
                        <td>
                          <div class="peer-label">{p.label || "—"}</div>
                          <div class="peer-id mono" title={p.device_id}>
                            {shortId(p.device_id)}
                          </div>
                        </td>
                        <td class="status" data-status={p.status}>
                          {p.status.replace("_", " ")}
                        </td>
                        <td>{p.authenticated ? "✓" : "—"}</td>
                        <td>{p.rtt_ms == null ? "—" : p.rtt_ms + "ms"}</td>
                        <td>
                          {p.local_shelved && p.remote_shelved
                            ? "both"
                            : p.local_shelved
                              ? "by us"
                              : p.remote_shelved
                                ? "by peer"
                                : "—"}
                        </td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              {/if}
            </div>
          {:else if tab === "roster"}
            <NetworkRosterPanel network={selected} />
          {:else if tab === "governance"}
            <NetworkGovernancePanel network={selected} />
          {/if}
        {/key}
      {/if}
    {/if}
  </div>
</div>

{#if showAddModal}
  <AddNetworkModal
    onClose={() => (showAddModal = false)}
    onAdded={(configId: string) => {
      showAddModal = false;
      selectedConfigId = configId;
    }}
  />
{/if}

<style>
  .section {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
  }
  .h-tabs {
    display: flex;
    align-items: center;
    border-bottom: 1px solid #1e1e1e;
    flex-shrink: 0;
    gap: 0.25rem;
    padding-right: 0.5rem;
  }
  .h-tabs button {
    padding: 0.55rem 1rem;
    background: none;
    border: none;
    color: #666;
    font-size: 0.8rem;
    cursor: pointer;
    border-bottom: 2px solid transparent;
    flex: 0 0 auto;
  }
  .h-tabs button.active {
    color: #e8e8e8;
    border-bottom-color: #6e6ef7;
  }
  .gov-tab {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
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
  .content {
    flex: 1;
    min-width: 0;
    min-height: 0;
    overflow-y: auto;
    padding: 1rem;
  }
  .placeholder {
    color: #888;
    line-height: 1.6;
    max-width: 36rem;
    font-size: 0.85rem;
  }
  .placeholder .hint {
    color: #666;
    margin-top: 0.4rem;
  }
  .placeholder .primary {
    margin-top: 0.5rem;
    padding: 0.4rem 1rem;
    background: #2a2a55;
    border: 1px solid #4a4a85;
    border-radius: 5px;
    color: #e8e8ff;
    cursor: pointer;
    font: inherit;
    font-size: 0.82rem;
    font-weight: 500;
  }
  .placeholder .primary:hover {
    background: #3a3a70;
    border-color: #6e6ef7;
  }
  .picker {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    margin-bottom: 1rem;
    font-size: 0.85rem;
  }
  .picker label {
    color: #888;
  }
  .picker select {
    background: #131318;
    color: #e8e8e8;
    border: 1px solid #2a2a30;
    border-radius: 5px;
    padding: 0.3rem 0.5rem;
    font: inherit;
    font-size: 0.82rem;
    min-width: 22rem;
  }
  .picker .add {
    margin-left: auto;
    padding: 0.3rem 0.7rem;
    background: #1a1a22;
    border: 1px solid #2a2a35;
    border-radius: 5px;
    color: #ccc;
    cursor: pointer;
    font: inherit;
    font-size: 0.78rem;
  }
  .picker .add:hover {
    border-color: #6e6ef7;
    color: #b8b8ff;
  }
  .card {
    background: #131318;
    border: 1px solid #1e1e25;
    border-radius: 8px;
    padding: 0.85rem 1rem;
  }
  .peers {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.82rem;
  }
  .peers thead th {
    text-align: left;
    color: #888;
    font-weight: 500;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    padding: 0.35rem 0.6rem;
    border-bottom: 1px solid #1e1e25;
  }
  .peers tbody td {
    padding: 0.55rem 0.6rem;
    border-bottom: 1px solid #18181c;
    vertical-align: top;
  }
  .peers tbody tr:last-child td {
    border-bottom: none;
  }
  .peer-label {
    font-weight: 500;
  }
  .peer-id {
    color: #777;
    font-size: 0.72rem;
  }
  .mono {
    font-family: ui-monospace, SFMono-Regular, monospace;
  }
  .status {
    text-transform: capitalize;
  }
  .status[data-status="active"] {
    color: #b9f5cc;
  }
  .status[data-status="shelved"],
  .status[data-status="pending_approval"] {
    color: #fbbf24;
  }
  .status[data-status="reconnecting"],
  .status[data-status="handshaking"],
  .status[data-status="sighted"] {
    color: #60a5fa;
  }
  .status[data-status="offline"] {
    color: #6b7280;
  }
  .status[data-status="error"] {
    color: #fca5a5;
  }
  .empty {
    color: #666;
    font-style: italic;
    padding: 0.6rem 0;
    font-size: 0.85rem;
  }
</style>
