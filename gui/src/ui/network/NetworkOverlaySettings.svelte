<script lang="ts">
  /** Edit-network panel — the first real "change a saved network's
   *  knobs" surface in the GUI. Until this landed, the only path to
   *  a new label or a new TURN URL was hand-editing
   *  `~/.myownmesh/config.json` and bouncing the daemon.
   *
   *  Mechanism: edit-network goes through a `networkRemove` +
   *  `networkAdd` with the same `network_id` (and so the same
   *  on-disk roster file, since rosters are keyed by `network_id`).
   *  Peers see a brief disconnect; the next ACTIVE re-handshake
   *  finds them in the roster again and skips re-approval. A proper
   *  atomic `mesh_network_update` is a follow-up — this gets users
   *  the affordance immediately without engine work. */

  import { save as saveDialog } from "@tauri-apps/plugin-dialog";
  import { meshClient } from "../../mesh-client.svelte";
  import { governance } from "../../network-governance.svelte";
  import {
    buildNetworkConfig,
    DEFAULT_NETWORK_STUN,
    exportNetworkSettings,
    type TurnEntry,
  } from "../../network-settings";
  import {
    buildTopology,
    type NetworkConfigInput,
    type NetworkSummary,
  } from "../../types";

  const {
    network,
  }: {
    network: NetworkSummary;
  } = $props();

  // ---- editable draft (seeded once per network) -----------------------

  let labelDraft = $state("");
  let topology = $state<"ring" | "star" | "full_mesh">("ring");
  let starHub = $state("");
  let signalingDraft = $state<string[]>([]);
  let stunDraft = $state<string[]>([]);
  let turnDraft = $state<TurnEntry[]>([]);
  let turnEntry = $state<TurnEntry>({ url: "", username: "", credential: "" });
  let autoApprove = $state(false);

  let loaded = $state(false);
  let busy = $state(false);
  let actionError = $state<string | null>(null);
  let savedAt = $state<number | null>(null);
  /** Last-known full config from the daemon. Snapshotted on load
   *  so the save flow can roll back to it if the new config fails
   *  to apply (and so an orphan record can carry it forward if
   *  the rollback itself fails — see `save()`). */
  let originalConfig = $state<NetworkConfigInput | null>(null);

  /** Seed the draft from the daemon's current config the first time
   *  we render. Re-seed when the user switches to a different
   *  network — the parent overlay remounts us via a `key={config_id}`
   *  block, so this `$effect` fires once per mount. */
  $effect(() => {
    if (loaded) return;
    void (async () => {
      try {
        const cfg = await meshClient.configShow();
        const net = cfg.networks.find(
          (n: NetworkConfigInput) =>
            n.id === network.config_id || n.network_id === network.network_id,
        );
        if (net) {
          originalConfig = net;
          seedFrom(net);
        } else {
          seedDefaults();
        }
      } catch (e) {
        actionError = `couldn't load current config: ${String(e)}`;
        seedDefaults();
      } finally {
        loaded = true;
      }
    })();
  });

  function seedFrom(cfg: NetworkConfigInput) {
    labelDraft = cfg.label ?? "";
    if (cfg.topology) {
      topology = cfg.topology.kind === "full_mesh" ? "full_mesh" : cfg.topology.kind;
      if (cfg.topology.kind === "star") starHub = cfg.topology.hub;
    } else {
      topology = "ring";
    }
    signalingDraft = cfg.signaling?.servers ?? [];
    stunDraft = (cfg.stun_servers ?? []).flatMap((s) => s.urls);
    if (stunDraft.length === 0) stunDraft = [...DEFAULT_NETWORK_STUN];
    turnDraft = (cfg.turn_servers ?? []).map((t) => ({
      url: t.urls[0] ?? "",
      ...(t.username ? { username: t.username } : {}),
      ...(t.credential ? { credential: t.credential } : {}),
    }));
    autoApprove = cfg.auto_approve ?? false;
  }

  function seedDefaults() {
    labelDraft = network.label ?? "";
    topology = "ring";
    signalingDraft = [];
    stunDraft = [...DEFAULT_NETWORK_STUN];
    turnDraft = [];
    autoApprove = false;
  }

  // ---- relay/STUN/TURN list editors -----------------------------------

  let signalingInput = $state("");
  let stunInput = $state("");

  function addSignaling() {
    const v = signalingInput.trim();
    if (!v) return;
    if (!/^wss?:\/\//i.test(v)) {
      actionError = "Signaling URL must start with ws:// or wss://";
      return;
    }
    if (signalingDraft.includes(v)) return;
    signalingDraft = [...signalingDraft, v];
    signalingInput = "";
    actionError = null;
  }
  function removeSignaling(url: string) {
    signalingDraft = signalingDraft.filter((u) => u !== url);
  }

  function addStun() {
    const v = stunInput.trim();
    if (!v) return;
    if (!/^stun:/i.test(v)) {
      actionError = "STUN URL must start with stun:";
      return;
    }
    if (stunDraft.includes(v)) return;
    stunDraft = [...stunDraft, v];
    stunInput = "";
    actionError = null;
  }
  function removeStun(url: string) {
    stunDraft = stunDraft.filter((u) => u !== url);
  }

  function addTurn() {
    const url = turnEntry.url.trim();
    if (!url) return;
    if (!/^turns?:/i.test(url)) {
      actionError = "TURN URL must start with turn: or turns:";
      return;
    }
    turnDraft = [
      ...turnDraft,
      {
        url,
        ...(turnEntry.username ? { username: turnEntry.username } : {}),
        ...(turnEntry.credential ? { credential: turnEntry.credential } : {}),
      },
    ];
    turnEntry = { url: "", username: "", credential: "" };
    actionError = null;
  }
  function removeTurn(url: string) {
    turnDraft = turnDraft.filter((t) => t.url !== url);
  }

  function resetStun() {
    stunDraft = [...DEFAULT_NETWORK_STUN];
  }

  // ---- save (remove + re-add with same network_id) --------------------

  async function save() {
    if (busy) return;
    busy = true;
    actionError = null;
    let newCfg: NetworkConfigInput;
    try {
      // Build the new wire payload first so we don't tear down the
      // current network just to find the inputs invalid.
      const topo = buildTopology(topology, starHub || null);
      newCfg = buildNetworkConfig({
        networkId: network.network_id,
        label: labelDraft,
        topology: topo,
        signalingServers: signalingDraft.filter((s) => s.trim() !== ""),
        stunUrls: stunDraft,
        turnEntries: turnDraft,
        autoApprove,
      });
    } catch (e) {
      actionError = `Invalid config: ${String(e)}`;
      busy = false;
      return;
    }

    // Edit = remove + re-add. The roster file lives at
    // `~/.myownmesh/mesh/rosters/{network_id}.json` on disk and is
    // keyed by network_id (not the local config record id), so it
    // survives the round-trip. The risk is the add step failing
    // (e.g. bad TURN URL the daemon rejects on parse) — without
    // care, that leaves the user with no network and no surface
    // to recover from. We snapshot the original on load, attempt
    // remove + new add, fall back to re-adding the original, and
    // record an orphan if even that fails.
    //
    // A proper atomic `mesh_network_update` would be cleaner. This
    // gets the user the affordance immediately without engine work.
    try {
      await meshClient.networkRemove(network.config_id);
    } catch (e) {
      actionError = `Couldn't remove existing config: ${String(e)}`;
      busy = false;
      return;
    }

    try {
      await meshClient.networkAdd(newCfg);
      savedAt = Date.now();
    } catch (addErr) {
      // New config rejected by the daemon — try to put the user
      // back where they were.
      if (originalConfig) {
        try {
          await meshClient.networkAdd(originalConfig);
          actionError = `Save failed; rolled back to previous config. (${String(addErr)})`;
        } catch (rollbackErr) {
          // Both failed. Stash the original so the user can retry
          // from the sidebar's orphan section instead of losing
          // the network entirely.
          governance.recordOrphan({
            config_id: network.config_id,
            network_id: network.network_id,
            label: network.label,
            failed_at: Date.now(),
            reason: `save: ${String(addErr)} · rollback: ${String(rollbackErr)}`,
            config: originalConfig,
          });
          actionError =
            `Save failed AND rollback failed. The network has been removed ` +
            `from the daemon and is recoverable from the "Failed saves" ` +
            `section in the sidebar.\n\n` +
            `save: ${String(addErr)}\nrollback: ${String(rollbackErr)}`;
        }
      } else {
        actionError = `Save failed and no rollback snapshot was available: ${String(addErr)}`;
      }
    } finally {
      busy = false;
    }
  }

  // ---- remove (danger zone) ------------------------------------------

  /** Two-click remove: the first click expands a confirm-shaped row.
   *  Modelled on the legacy NetworksSection pattern so users moving
   *  between the two surfaces don't relearn the muscle memory. */
  let confirmingRemove = $state(false);

  async function removeNetwork() {
    if (busy) return;
    busy = true;
    actionError = null;
    try {
      await meshClient.networkRemove(network.config_id);
      // Drop any orphan tracking we had for this network — the
      // user has explicitly chosen to forget it.
      governance.discardOrphan(network.network_id);
      // The overlay's parent watches `meshClient.networks`; when
      // this config_id disappears, the overlay closes itself
      // (via the "network not found" empty state). No explicit
      // onClose call needed.
    } catch (e) {
      actionError = `Remove failed: ${String(e)}`;
    } finally {
      busy = false;
    }
  }

  // ---- export (share network settings to another device) --------------

  async function exportNetwork() {
    if (busy) return;
    busy = true;
    actionError = null;
    try {
      // Pull from the daemon so the export carries the live
      // signaling/STUN/TURN — not the user's unsaved drafts.
      // (If the user wants to share their pending edits before
      // saving, they save first, then export. Two clicks; cleaner
      // mental model than "export draft state.")
      const cfg = await meshClient.configShow();
      const net = cfg.networks.find(
        (n: NetworkConfigInput) =>
          n.id === network.config_id || n.network_id === network.network_id,
      );
      if (!net) {
        actionError =
          "Network is live in the registry but the daemon has no saved " +
          "config to export. Save first, then export.";
        return;
      }
      const envelope = exportNetworkSettings(net);
      const path = await saveDialog({
        defaultPath: `${envelope.network_id || net.id}.network-settings.json`,
        filters: [{ name: "MyOwnMesh network settings", extensions: ["json"] }],
      });
      if (!path) return; // user cancelled
      await meshClient.exportNetworkFile(path, envelope);
    } catch (e) {
      actionError = `Export failed: ${String(e)}`;
    } finally {
      busy = false;
    }
  }
</script>

<div class="tab">
  <div class="hint">
    Editing a network reapplies the new config to the daemon. The
    roster (and so every peer you've already approved) survives the
    round-trip — peers will reconnect within a few seconds. For
    transient changes use the per-tab quick-toggles instead.
  </div>

  {#if actionError}
    <div class="err">⚠ {actionError}</div>
  {/if}

  {#if savedAt}
    <div class="ok">
      ✓ saved · peers reconnecting…
    </div>
  {/if}

  {#if !loaded}
    <div class="card muted">Loading current config…</div>
  {:else}
    <!-- Identity -->
    <div class="card">
      <div class="card-title">Identity</div>
      <label class="field">
        <span class="field-label">Label</span>
        <input
          type="text"
          placeholder="Cosmetic name — e.g. 'Home'"
          bind:value={labelDraft}
        />
      </label>
      <label class="field">
        <span class="field-label">Network ID</span>
        <input
          type="text"
          value={network.network_id}
          readonly
          class="mono readonly"
          title="The network ID is the wire-level rendezvous handle. Changing it would create a different network — use the Remove + Add flow instead."
        />
      </label>
    </div>

    <!-- Topology -->
    <div class="card">
      <div class="card-title">Topology</div>
      <div class="topo-row">
        <button
          class="topo-btn"
          class:active={topology === "ring"}
          onclick={() => (topology = "ring")}
        >
          Ring
        </button>
        <button
          class="topo-btn"
          class:active={topology === "full_mesh"}
          onclick={() => (topology = "full_mesh")}
        >
          Full mesh
        </button>
        <button
          class="topo-btn"
          class:active={topology === "star"}
          onclick={() => (topology = "star")}
        >
          Star
        </button>
      </div>
      {#if topology === "star"}
        <label class="field" style="margin-top: 0.5rem">
          <span class="field-label">Hub device id</span>
          <input
            type="text"
            placeholder="base32-lowercase pubkey"
            bind:value={starHub}
            class="mono"
          />
        </label>
      {/if}
    </div>

    <!-- Signaling relays -->
    <div class="card">
      <div class="card-title">Signaling relays</div>
      <div class="hint subtle">
        Leave empty to use the built-in Nostr relay pool. Add your own
        WebSocket URLs (<code>wss://...</code>) to pin specific
        relays — they take full precedence over the defaults.
      </div>
      {#each signalingDraft as url (url)}
        <div class="list-row">
          <code class="mono row-text">{url}</code>
          <button class="row-btn danger" onclick={() => removeSignaling(url)}>
            Remove
          </button>
        </div>
      {/each}
      <div class="add-row">
        <input
          type="text"
          placeholder="wss://relay.example.com"
          bind:value={signalingInput}
          onkeydown={(e) => e.key === "Enter" && addSignaling()}
        />
        <button class="row-btn" onclick={addSignaling}>Add</button>
      </div>
    </div>

    <!-- STUN -->
    <div class="card">
      <div class="card-title">
        STUN servers
        <button class="reset" onclick={resetStun} title="Reset to defaults">
          reset
        </button>
      </div>
      {#each stunDraft as url (url)}
        <div class="list-row">
          <code class="mono row-text">{url}</code>
          <button class="row-btn danger" onclick={() => removeStun(url)}>
            Remove
          </button>
        </div>
      {/each}
      <div class="add-row">
        <input
          type="text"
          placeholder="stun:stun.example.com:3478"
          bind:value={stunInput}
          onkeydown={(e) => e.key === "Enter" && addStun()}
        />
        <button class="row-btn" onclick={addStun}>Add</button>
      </div>
    </div>

    <!-- TURN -->
    <div class="card">
      <div class="card-title">TURN servers</div>
      <div class="hint subtle">
        Needed for peers behind symmetric NAT (most common on phone
        hotspots). MyOwnMesh ships <strong>no default TURN</strong> —
        bring your own or use Cloudflare Calls / Open Relay Project /
        self-hosted Coturn.
      </div>
      {#each turnDraft as t (t.url)}
        <div class="list-row turn">
          <div class="turn-fields">
            <code class="mono">{t.url}</code>
            {#if t.username}
              <span class="muted">user: {t.username}</span>
            {/if}
          </div>
          <button class="row-btn danger" onclick={() => removeTurn(t.url)}>
            Remove
          </button>
        </div>
      {/each}
      <div class="turn-add">
        <input
          type="text"
          placeholder="turn:your-host:3478"
          bind:value={turnEntry.url}
        />
        <input
          type="text"
          placeholder="username"
          bind:value={turnEntry.username}
        />
        <input
          type="text"
          placeholder="credential"
          bind:value={turnEntry.credential}
        />
        <button class="row-btn" onclick={addTurn}>Add</button>
      </div>
    </div>

    <!-- Auto-approve -->
    <div class="card">
      <div class="card-title">Approval policy</div>
      <label class="checkbox">
        <input type="checkbox" bind:checked={autoApprove} />
        <span>
          <strong>Auto-approve incoming peers</strong>
          <span class="muted-inline">
            — every new peer lands in the roster automatically. Useful
            for headless fleet nodes; not recommended on user-facing
            devices.
          </span>
        </span>
      </label>
    </div>

    <!-- Save / Export -->
    <div class="actions">
      <button
        class="btn ghost"
        disabled={busy}
        onclick={exportNetwork}
        title="Export this network's settings as a JSON file another device can import to join the same network."
      >
        Export…
      </button>
      <button class="btn primary" disabled={busy} onclick={save}>
        {busy ? "Saving…" : "Save changes"}
      </button>
    </div>

    <div class="hint subtle bottom-hint">
      <strong>Sharing this network.</strong> Use <strong>Export…</strong>
      to write a <code>.network-settings.json</code> file you can
      send to another device — they import it via
      <em>Sidebar → + → Import…</em> to join the same network. For
      out-of-band pre-authorisation (so a new device's first
      connection is auto-approved), use the
      <strong>Approval</strong> action on a rostered peer in the
      Roster tab.
    </div>

    <!-- Danger zone: a clear, sticky path to remove a network from
         the daemon. Lives at the bottom so it's hard to miss but
         also hard to hit by accident; the two-click confirm-then-
         commit shape mirrors the existing legacy Networks tab. -->
    <div class="danger-zone">
      <div class="danger-title">Danger zone</div>
      {#if confirmingRemove}
        <div class="danger-row">
          <span class="danger-text">
            Remove this network from the daemon? The local roster
            file is preserved on disk and a re-add with the same
            network ID will pick it up again.
          </span>
          <div class="danger-actions">
            <button
              class="btn danger"
              disabled={busy}
              onclick={removeNetwork}
            >
              {busy ? "Removing…" : "Confirm remove"}
            </button>
            <button
              class="btn ghost"
              disabled={busy}
              onclick={() => (confirmingRemove = false)}
            >
              Cancel
            </button>
          </div>
        </div>
      {:else}
        <div class="danger-row">
          <span class="danger-text">
            Stop joining this network and drop it from the daemon's
            registry. Roster file on disk is preserved.
          </span>
          <button
            class="btn danger"
            disabled={busy}
            onclick={() => (confirmingRemove = true)}
          >
            Remove network…
          </button>
        </div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .tab {
    display: flex;
    flex-direction: column;
    gap: 0.7rem;
  }
  .hint {
    color: #b8c5d0;
    background: #131820;
    border: 1px solid #1c2630;
    border-radius: 6px;
    padding: 0.55rem 0.7rem;
    font-size: 0.79rem;
    line-height: 1.45;
  }
  .hint.subtle {
    background: none;
    border: none;
    color: #888;
    padding: 0 0 0.4rem;
    font-size: 0.76rem;
  }
  .hint.subtle code {
    background: #131318;
    padding: 0.02rem 0.3rem;
    border-radius: 3px;
    font-size: 0.74rem;
  }
  .err {
    background: #3a1717;
    color: #ffb4b4;
    border: 1px solid #5a2424;
    border-radius: 5px;
    padding: 0.45rem 0.6rem;
    font-size: 0.8rem;
  }
  .ok {
    background: #112a1c;
    color: #b9f5cc;
    border: 1px solid #1c4a30;
    border-radius: 5px;
    padding: 0.45rem 0.6rem;
    font-size: 0.8rem;
  }
  .card {
    background: #131318;
    border: 1px solid #1e1e25;
    border-radius: 8px;
    padding: 0.7rem 0.9rem;
  }
  .card.muted {
    color: #888;
    font-style: italic;
  }
  .card-title {
    font-weight: 600;
    font-size: 0.82rem;
    margin-bottom: 0.55rem;
    color: #ccc;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .reset {
    background: none;
    border: 1px solid #2a2a35;
    color: #888;
    cursor: pointer;
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    padding: 0.12rem 0.5rem;
    border-radius: 4px;
  }
  .reset:hover {
    color: #ccc;
    border-color: #4a4a55;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    margin-bottom: 0.55rem;
    font-size: 0.82rem;
  }
  .field:last-child {
    margin-bottom: 0;
  }
  .field-label {
    color: #888;
    font-size: 0.74rem;
  }
  input[type="text"] {
    background: #0d0d12;
    border: 1px solid #2a2a35;
    color: #e8e8e8;
    padding: 0.35rem 0.55rem;
    border-radius: 5px;
    font: inherit;
    font-size: 0.82rem;
  }
  input.mono {
    font-family: ui-monospace, SFMono-Regular, monospace;
    font-size: 0.76rem;
  }
  input.readonly {
    color: #888;
    cursor: not-allowed;
  }
  input[type="text"]:focus {
    outline: none;
    border-color: #4a4a85;
  }
  .topo-row {
    display: flex;
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
  .topo-btn:hover:not(.active) {
    border-color: #4a4a55;
    color: #e8e8e8;
  }
  .list-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.3rem 0;
    border-bottom: 1px solid #1a1a20;
  }
  .list-row:last-child {
    border-bottom: none;
  }
  .row-text {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 0.76rem;
  }
  .mono {
    font-family: ui-monospace, SFMono-Regular, monospace;
  }
  .row-btn {
    padding: 0.2rem 0.55rem;
    background: #1a1a22;
    border: 1px solid #2a2a35;
    border-radius: 4px;
    color: #ccc;
    cursor: pointer;
    font: inherit;
    font-size: 0.72rem;
  }
  .row-btn.danger {
    color: #fca5a5;
    border-color: #4a2222;
  }
  .row-btn.danger:hover {
    background: #2a1414;
  }
  .row-btn:hover:not(.danger) {
    border-color: #4a4a55;
    color: #e8e8e8;
  }
  .add-row {
    display: flex;
    gap: 0.4rem;
    margin-top: 0.4rem;
  }
  .add-row input {
    flex: 1;
  }
  .turn .turn-fields {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
  }
  .turn .turn-fields .mono {
    font-size: 0.76rem;
  }
  .muted {
    color: #888;
    font-size: 0.72rem;
  }
  .muted-inline {
    color: #888;
    font-size: 0.78rem;
  }
  .turn-add {
    display: grid;
    grid-template-columns: 2fr 1fr 1fr auto;
    gap: 0.4rem;
    margin-top: 0.5rem;
  }
  .checkbox {
    display: flex;
    align-items: flex-start;
    gap: 0.55rem;
    font-size: 0.82rem;
    cursor: pointer;
  }
  .checkbox input {
    margin-top: 0.2rem;
  }
  .actions {
    display: flex;
    gap: 0.5rem;
    padding-top: 0.5rem;
    justify-content: flex-end;
  }
  .btn {
    padding: 0.5rem 1.1rem;
    border-radius: 5px;
    border: 1px solid #2a2a35;
    background: #1a1a22;
    color: #ccc;
    cursor: pointer;
    font: inherit;
    font-size: 0.84rem;
  }
  .btn.primary {
    background: #2a2a55;
    border-color: #4a4a85;
    color: #e8e8ff;
    font-weight: 500;
  }
  .btn.primary:hover {
    background: #3a3a70;
    border-color: #6e6ef7;
  }
  .btn.ghost {
    background: none;
  }
  .btn:disabled {
    opacity: 0.5;
    cursor: default;
  }
  .bottom-hint {
    margin-top: 0.5rem;
  }
  .bottom-hint code {
    background: #131318;
    padding: 0.02rem 0.3rem;
    border-radius: 3px;
    font-size: 0.74rem;
  }
  .danger-zone {
    margin-top: 1.2rem;
    background: #1d1414;
    border: 1px solid #3a1f1f;
    border-radius: 8px;
    padding: 0.7rem 0.9rem;
  }
  .danger-title {
    color: #fca5a5;
    font-weight: 600;
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 0.5rem;
  }
  .danger-row {
    display: flex;
    align-items: center;
    gap: 0.7rem;
    flex-wrap: wrap;
  }
  .danger-text {
    flex: 1;
    color: #ccc;
    font-size: 0.78rem;
    line-height: 1.4;
    min-width: 14rem;
  }
  .danger-actions {
    display: flex;
    gap: 0.4rem;
  }
  .btn.danger {
    background: #2a1414;
    border-color: #5a2424;
    color: #fca5a5;
  }
  .btn.danger:hover:not(:disabled) {
    background: #3a1717;
    border-color: #7a3434;
  }
</style>
