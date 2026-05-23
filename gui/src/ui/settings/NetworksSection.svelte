<script lang="ts">
  import { meshClient } from "../../mesh-client.svelte";
  import { topologyName, topologyHub } from "../../types";
  import type { AuthorizedPeer, NetworkSummary, PeerInfo } from "../../types";

  const {
    focusedConfigId,
  }: {
    focusedConfigId: string | null;
  } = $props();

  type SubTab = "status" | "connections" | "roster";

  /** Sub-tab strip mirrors MyOwnLLM's CloudMeshSection — Status is
   *  the everyday surface (network list + topology selector),
   *  Connections is the per-peer detail, Roster lets the user
   *  approve / remove authorized devices. */
  // svelte-ignore state_referenced_locally
  let tab = $state<SubTab>("status");

  /** Which saved network the detail panes operate on. Defaults to
   *  whatever the node-map is currently showing; user can switch
   *  via the picker at the top. */
  // svelte-ignore state_referenced_locally
  let selectedConfigId = $state<string | null>(focusedConfigId);

  $effect(() => {
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

  // Roster contents — fetched lazily on tab open and refreshed
  // after approve/remove. Keeping it locally inside the component
  // (rather than on the global mesh client) keeps the API surface
  // small; only this tab needs to render it.
  let roster = $state<AuthorizedPeer[]>([]);
  let rosterError = $state<string | null>(null);

  async function refreshRoster() {
    if (!selected) {
      roster = [];
      return;
    }
    try {
      roster = await meshClient.rosterList(selected.config_id);
      rosterError = null;
    } catch (e) {
      rosterError = String(e);
    }
  }

  $effect(() => {
    if (tab === "roster") {
      void refreshRoster();
    }
  });

  let busy = $state(false);
  let actionError = $state<string | null>(null);

  async function setTopology(
    topo: "ring" | "star" | "full_mesh",
    hub?: string,
  ) {
    if (!selected) return;
    busy = true;
    actionError = null;
    try {
      await meshClient.topologySet(selected.config_id, topo, hub);
    } catch (e) {
      actionError = String(e);
    } finally {
      busy = false;
    }
  }

  async function approve(deviceId: string, label?: string) {
    if (!selected) return;
    busy = true;
    actionError = null;
    try {
      await meshClient.rosterApprove(selected.config_id, deviceId, label);
      await refreshRoster();
    } catch (e) {
      actionError = String(e);
    } finally {
      busy = false;
    }
  }

  async function remove(deviceId: string) {
    if (!selected) return;
    busy = true;
    actionError = null;
    try {
      await meshClient.rosterRemove(selected.config_id, deviceId);
      await refreshRoster();
    } catch (e) {
      actionError = String(e);
    } finally {
      busy = false;
    }
  }

  function shortId(id: string): string {
    if (id.length <= 16) return id;
    return id.slice(0, 8) + "…" + id.slice(-6);
  }

  function fmtDate(epoch: number): string {
    return new Date(epoch * 1000).toLocaleString();
  }
</script>

<div class="section">
  <div class="h-tabs">
    <button class:active={tab === "status"} onclick={() => (tab = "status")}>
      Status
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
  </div>

  <div class="content">
    {#if meshClient.networks.length === 0}
      <div class="placeholder">
        <p>No networks joined yet.</p>
        <p class="hint">
          Add one to <code>~/.myownmesh/config.json</code> under
          <code>networks: []</code>, then restart <code>myownmesh serve</code>.
          A future build will let you add networks directly from this panel.
        </p>
      </div>
    {:else}
      <div class="picker">
        <label for="net-picker">Network</label>
        <select id="net-picker" bind:value={selectedConfigId}>
          {#each meshClient.networks as n}
            <option value={n.config_id}>{n.config_id} — {n.network_id}</option>
          {/each}
        </select>
      </div>

      {#if actionError}
        <div class="err">⚠ {actionError}</div>
      {/if}

      {#if selected}
        {#if tab === "status"}
          <div class="card">
            <div class="card-title">{selected.config_id}</div>
            <dl class="grid">
              <dt>Network ID</dt>
              <dd class="mono break">{selected.network_id}</dd>
              <dt>Phase</dt>
              <dd>
                <span class="phase" data-phase={selected.phase}>
                  {selected.phase.replace("_", " ")}
                </span>
              </dd>
              <dt>Topology</dt>
              <dd>
                <div class="topo-row">
                  <button
                    class="topo-btn"
                    class:active={topologyName(selected.topology) === "ring"}
                    disabled={busy}
                    onclick={() => setTopology("ring")}
                  >
                    Ring
                  </button>
                  <button
                    class="topo-btn"
                    class:active={topologyName(selected.topology) === "full_mesh"}
                    disabled={busy}
                    onclick={() => setTopology("full_mesh")}
                  >
                    Full mesh
                  </button>
                  <button
                    class="topo-btn"
                    class:active={topologyName(selected.topology) === "star"}
                    disabled={busy || peers.length === 0}
                    onclick={() => {
                      // Star needs a hub. Default to the first
                      // active peer; the user can re-target via the
                      // Connections tab's per-peer "make hub" action
                      // (TODO — currently the only path is via
                      // config.json).
                      const hub =
                        peers.find((p) => p.status === "active")?.device_id ??
                        peers[0]?.device_id;
                      if (hub) setTopology("star", hub);
                      else actionError = "no peers available to use as hub";
                    }}
                    title="Star needs a hub peer — picks the first active peer"
                  >
                    Star
                  </button>
                </div>
                {#if topologyName(selected.topology) === "star"}
                  <div class="topo-hub">
                    hub · <span class="mono">{topologyHub(selected.topology)}</span>
                  </div>
                {/if}
              </dd>
              <dt>Peers</dt>
              <dd>{peers.length} tracked</dd>
            </dl>
          </div>
        {:else if tab === "connections"}
          <div class="card">
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
                    <th></th>
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
                      <td>
                        <button
                          class="row-btn"
                          disabled={busy || !p.authenticated}
                          onclick={() => approve(p.device_id, p.label)}
                          title="Approve into the roster"
                        >
                          Approve
                        </button>
                      </td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            {/if}
          </div>
        {:else if tab === "roster"}
          <div class="card">
            {#if rosterError}
              <div class="err">⚠ {rosterError}</div>
            {/if}
            {#if roster.length === 0}
              <div class="empty">No approved devices yet.</div>
            {:else}
              <table class="peers">
                <thead>
                  <tr>
                    <th>Device</th>
                    <th>Approved</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {#each roster as r (r.device_id)}
                    <tr>
                      <td>
                        <div class="peer-label">{r.label || "—"}</div>
                        <div class="peer-id mono" title={r.device_id}>
                          {shortId(r.device_id)}
                        </div>
                      </td>
                      <td>{fmtDate(r.approved_at)}</td>
                      <td>
                        <button
                          class="row-btn danger"
                          disabled={busy}
                          onclick={() => remove(r.device_id)}
                        >
                          Remove
                        </button>
                      </td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            {/if}
          </div>
        {/if}
      {/if}
    {/if}
  </div>
</div>

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
  .err {
    background: #3a1717;
    color: #ffb4b4;
    border: 1px solid #5a2424;
    border-radius: 5px;
    padding: 0.45rem 0.6rem;
    font-size: 0.8rem;
    margin-bottom: 1rem;
  }
  .card {
    background: #131318;
    border: 1px solid #1e1e25;
    border-radius: 8px;
    padding: 0.85rem 1rem;
  }
  .card-title {
    font-weight: 600;
    font-size: 0.92rem;
    margin-bottom: 0.7rem;
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
  .topo-row {
    display: inline-flex;
    gap: 0.4rem;
    flex-wrap: wrap;
  }
  .topo-btn {
    padding: 0.3rem 0.7rem;
    background: #1a1a22;
    border: 1px solid #2a2a35;
    border-radius: 5px;
    color: #ccc;
    cursor: pointer;
    font: inherit;
    font-size: 0.78rem;
  }
  .topo-btn.active {
    background: #1a1a2a;
    border-color: #6e6ef7;
    color: #b8b8ff;
  }
  .topo-btn:hover:not(:disabled):not(.active) {
    border-color: #4a4a55;
    color: #e8e8e8;
  }
  .topo-btn:disabled {
    opacity: 0.5;
    cursor: default;
  }
  .topo-hub {
    margin-top: 0.45rem;
    font-size: 0.74rem;
    color: #888;
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
  .row-btn {
    padding: 0.25rem 0.6rem;
    background: #1a1a22;
    border: 1px solid #2a2a35;
    border-radius: 4px;
    color: #ccc;
    cursor: pointer;
    font: inherit;
    font-size: 0.75rem;
  }
  .row-btn:hover:not(:disabled) {
    border-color: #4a4a55;
    color: #e8e8e8;
  }
  .row-btn:disabled {
    opacity: 0.5;
    cursor: default;
  }
  .row-btn.danger {
    color: #fca5a5;
    border-color: #4a2222;
  }
  .row-btn.danger:hover:not(:disabled) {
    background: #2a1414;
  }
  .empty {
    color: #666;
    font-style: italic;
    padding: 0.6rem 0;
    font-size: 0.85rem;
  }
</style>
