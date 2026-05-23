<script lang="ts">
  import { meshClient } from "../../mesh-client.svelte";
  import { buildTopology, type NetworkConfigInput } from "../../types";
  import { open as openDialog } from "@tauri-apps/plugin-dialog";

  const {
    onClose,
    onAdded,
  }: {
    onClose: () => void;
    onAdded: (configId: string) => void;
  } = $props();

  /** Form state. We start with sane defaults so a user can hit
   *  "Create" with just a network_id and label and get a working
   *  network. Import-from-file fills the same fields, then the
   *  user reviews + commits — there's no separate "import" path
   *  that bypasses the form. */
  let id = $state("");
  let networkId = $state("");
  let label = $state("");
  let topology = $state<"ring" | "star" | "full_mesh">("ring");
  let starHub = $state("");
  let autoApprove = $state(false);
  /** Optional STUN servers — one per line. The Rust side accepts
   *  any URL the user types; we serialise as `[{ url }]`. */
  let stunInput = $state("");
  /** Pasted JSON. When non-empty, the "Paste JSON" button fills the
   *  form from it. We don't auto-parse on every keystroke; the user
   *  hits a button to commit it. */
  let pasteJson = $state("");

  let busy = $state(false);
  let error = $state<string | null>(null);

  /** Pre-fill the form from an arbitrary NetworkConfig JSON object.
   *  Used by both "Import from file" and "Paste JSON". Lenient —
   *  missing fields just keep their current value. */
  function fillFromConfig(cfg: NetworkConfigInput) {
    id = cfg.id ?? id;
    networkId = cfg.network_id ?? networkId;
    label = cfg.label ?? label;
    if (cfg.topology) {
      topology = cfg.topology.kind;
      if (cfg.topology.kind === "star") {
        starHub = cfg.topology.hub;
      }
    }
    if (typeof cfg.auto_approve === "boolean") autoApprove = cfg.auto_approve;
    if (Array.isArray(cfg.stun_servers)) {
      stunInput = cfg.stun_servers.map((s) => s.url).join("\n");
    }
  }

  async function importFromFile() {
    try {
      const picked = await openDialog({
        multiple: false,
        filters: [{ name: "JSON", extensions: ["json"] }],
      });
      if (!picked || Array.isArray(picked)) return;
      const cfg = await meshClient.importNetworkFile(picked);
      fillFromConfig(cfg);
      error = null;
    } catch (e) {
      error = String(e);
    }
  }

  function importFromPaste() {
    try {
      const parsed = JSON.parse(pasteJson) as NetworkConfigInput;
      fillFromConfig(parsed);
      pasteJson = "";
      error = null;
    } catch (e) {
      error = "Couldn't parse JSON: " + String(e);
    }
  }

  function buildConfig(): NetworkConfigInput | string {
    const trimmed = (s: string) => s.trim();
    const i = trimmed(id);
    const n = trimmed(networkId);
    if (!i) return "Config ID is required.";
    if (!n) return "Network ID is required.";
    if (topology === "star" && !trimmed(starHub))
      return "Star topology needs a hub device ID.";
    const stunServers = stunInput
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((url) => ({ url }));
    return {
      id: i,
      network_id: n,
      label: trimmed(label) || undefined,
      topology: buildTopology(topology, starHub.trim() || null),
      auto_approve: autoApprove,
      stun_servers: stunServers.length ? stunServers : undefined,
    };
  }

  async function submit() {
    const built = buildConfig();
    if (typeof built === "string") {
      error = built;
      return;
    }
    busy = true;
    error = null;
    try {
      await meshClient.networkAdd(built);
      onAdded(built.id);
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  function onBackdropClick(e: MouseEvent) {
    if (e.target === e.currentTarget && !busy) onClose();
  }
</script>

<!-- svelte-ignore a11y_click_events_have_key_events -->
<!-- svelte-ignore a11y_no_static_element_interactions -->
<div class="backdrop" onclick={onBackdropClick}>
  <div class="modal" role="dialog" aria-label="Add network">
    <div class="head">
      <h3>Add network</h3>
      <button class="close" onclick={onClose} aria-label="Close" disabled={busy}>
        ✕
      </button>
    </div>

    <div class="body">
      {#if error}
        <div class="err">⚠ {error}</div>
      {/if}

      <div class="actions-row">
        <button class="ghost" onclick={importFromFile} disabled={busy}>
          Import from file…
        </button>
        <span class="sep">or paste JSON ↓</span>
      </div>

      <textarea
        class="paste"
        placeholder={'{ "id": "home", "network_id": "my-mesh", "label": "Home" }'}
        bind:value={pasteJson}
        rows="3"
        disabled={busy}
      ></textarea>
      <button class="ghost small" onclick={importFromPaste} disabled={busy || !pasteJson.trim()}>
        Fill form from JSON
      </button>

      <hr />

      <div class="form">
        <label>
          <span>Config ID</span>
          <input
            type="text"
            bind:value={id}
            placeholder="home"
            disabled={busy}
            autocomplete="off"
          />
          <small>Unique on this device. Used to address this network in CLI / UI.</small>
        </label>

        <label>
          <span>Network ID</span>
          <input
            type="text"
            bind:value={networkId}
            placeholder="my-mesh-handle"
            disabled={busy}
            autocomplete="off"
          />
          <small>Wire-level rendezvous handle. Everyone joining the same mesh shares this.</small>
        </label>

        <label>
          <span>Label</span>
          <input
            type="text"
            bind:value={label}
            placeholder="Home mesh"
            disabled={busy}
            autocomplete="off"
          />
          <small>Cosmetic display name.</small>
        </label>

        <label>
          <span>Topology</span>
          <div class="topo-pick">
            <button
              class="topo"
              class:active={topology === "ring"}
              onclick={() => (topology = "ring")}
              disabled={busy}
            >
              Ring
            </button>
            <button
              class="topo"
              class:active={topology === "full_mesh"}
              onclick={() => (topology = "full_mesh")}
              disabled={busy}
            >
              Full mesh
            </button>
            <button
              class="topo"
              class:active={topology === "star"}
              onclick={() => (topology = "star")}
              disabled={busy}
            >
              Star
            </button>
          </div>
        </label>

        {#if topology === "star"}
          <label>
            <span>Star hub</span>
            <input
              type="text"
              bind:value={starHub}
              placeholder="device id of the hub"
              disabled={busy}
              autocomplete="off"
            />
            <small>Every spoke routes through this device.</small>
          </label>
        {/if}

        <label>
          <span>STUN servers</span>
          <textarea
            bind:value={stunInput}
            placeholder="stun:stun.l.google.com:19302"
            rows="2"
            disabled={busy}
          ></textarea>
          <small>One URL per line. Optional.</small>
        </label>

        <label class="check">
          <input
            type="checkbox"
            bind:checked={autoApprove}
            disabled={busy}
          />
          <span>Auto-approve every authenticating peer</span>
          <small>Useful for headless fleet members. Off by default.</small>
        </label>
      </div>
    </div>

    <div class="foot">
      <button class="ghost" onclick={onClose} disabled={busy}>Cancel</button>
      <button class="primary" onclick={submit} disabled={busy}>
        {busy ? "Adding…" : "Create network"}
      </button>
    </div>
  </div>
</div>

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.55);
    backdrop-filter: blur(4px);
    -webkit-backdrop-filter: blur(4px);
    z-index: 50;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .modal {
    background: #131320;
    border: 1px solid #2a2a40;
    border-radius: 12px;
    width: 36rem;
    max-width: calc(100% - 2rem);
    max-height: calc(100vh - 2rem);
    display: flex;
    flex-direction: column;
    box-shadow: 0 16px 40px rgba(0, 0, 0, 0.55);
  }
  .head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.75rem 1rem;
    border-bottom: 1px solid #1e1e28;
    flex-shrink: 0;
  }
  .head h3 {
    margin: 0;
    font-size: 0.95rem;
    font-weight: 600;
  }
  .close {
    background: none;
    border: none;
    color: #888;
    cursor: pointer;
    font-size: 1rem;
    padding: 0.25rem 0.4rem;
    border-radius: 4px;
  }
  .close:hover:not(:disabled) {
    background: #1a1a2a;
    color: #e8e8e8;
  }
  .body {
    flex: 1;
    overflow-y: auto;
    padding: 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  .actions-row {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    font-size: 0.78rem;
    color: #888;
  }
  .sep {
    color: #666;
  }
  .paste {
    background: #0d0d12;
    border: 1px solid #1e1e25;
    border-radius: 5px;
    color: #e0e0e0;
    padding: 0.5rem 0.6rem;
    font: inherit;
    font-family: ui-monospace, SFMono-Regular, monospace;
    font-size: 0.75rem;
    resize: vertical;
    min-height: 4rem;
  }
  .err {
    background: #3a1717;
    color: #ffb4b4;
    border: 1px solid #5a2424;
    border-radius: 5px;
    padding: 0.45rem 0.6rem;
    font-size: 0.78rem;
  }
  hr {
    border: none;
    border-top: 1px solid #1e1e28;
    margin: 0.25rem 0;
  }
  .form {
    display: flex;
    flex-direction: column;
    gap: 0.7rem;
  }
  .form label {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    font-size: 0.8rem;
    color: #aaa;
  }
  .form label > span {
    color: #ccc;
    font-weight: 500;
    font-size: 0.82rem;
  }
  .form input[type="text"],
  .form textarea {
    background: #0d0d12;
    border: 1px solid #2a2a30;
    border-radius: 5px;
    color: #e8e8e8;
    padding: 0.45rem 0.55rem;
    font: inherit;
    font-size: 0.82rem;
  }
  .form textarea {
    font-family: ui-monospace, SFMono-Regular, monospace;
    font-size: 0.75rem;
    resize: vertical;
    min-height: 2.5rem;
  }
  .form input:focus,
  .form textarea:focus {
    outline: none;
    border-color: #6e6ef7;
  }
  .form small {
    color: #666;
    font-size: 0.7rem;
  }
  .form .check {
    flex-direction: row;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
  }
  .form .check > input[type="checkbox"] {
    margin: 0;
    flex-shrink: 0;
  }
  .form .check > span {
    flex: 1;
    color: #ccc;
  }
  .form .check small {
    width: 100%;
    margin-top: 0.1rem;
  }
  .topo-pick {
    display: flex;
    gap: 0.4rem;
    flex-wrap: wrap;
  }
  .topo {
    padding: 0.3rem 0.7rem;
    background: #1a1a22;
    border: 1px solid #2a2a35;
    border-radius: 5px;
    color: #ccc;
    cursor: pointer;
    font: inherit;
    font-size: 0.78rem;
  }
  .topo.active {
    background: #1a1a2a;
    border-color: #6e6ef7;
    color: #b8b8ff;
  }
  .topo:hover:not(:disabled):not(.active) {
    border-color: #4a4a55;
    color: #e8e8e8;
  }
  .topo:disabled {
    opacity: 0.5;
    cursor: default;
  }
  .foot {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
    padding: 0.75rem 1rem;
    border-top: 1px solid #1e1e28;
    flex-shrink: 0;
  }
  .ghost {
    padding: 0.4rem 0.85rem;
    background: #1a1a22;
    border: 1px solid #2a2a35;
    border-radius: 5px;
    color: #ccc;
    cursor: pointer;
    font: inherit;
    font-size: 0.8rem;
  }
  .ghost.small {
    padding: 0.25rem 0.6rem;
    font-size: 0.72rem;
    align-self: flex-start;
  }
  .ghost:hover:not(:disabled) {
    border-color: #4a4a55;
    color: #e8e8e8;
  }
  .ghost:disabled {
    opacity: 0.5;
    cursor: default;
  }
  .primary {
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
  .primary:hover:not(:disabled) {
    background: #3a3a70;
    border-color: #6e6ef7;
  }
  .primary:disabled {
    opacity: 0.5;
    cursor: default;
  }
</style>
