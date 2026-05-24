<script lang="ts">
  import { meshClient } from "../../mesh-client.svelte";

  /** Inline edit state for the label. Starts in "view" mode; the
   *  user clicks "Edit" to swap to the input, then "Save" persists
   *  through the daemon and "Cancel" reverts. */
  let editing = $state(false);
  let draft = $state("");
  let saving = $state(false);
  let saveError = $state<string | null>(null);

  function startEditing() {
    draft = meshClient.identity?.label ?? "";
    saveError = null;
    editing = true;
  }

  function cancelEditing() {
    editing = false;
    saveError = null;
  }

  async function save() {
    if (saving) return;
    saving = true;
    saveError = null;
    try {
      // Trim whitespace before persisting — labels are user-facing
      // strings and trailing spaces look like file-system grime.
      // Empty after trim clears the label (the daemon accepts "").
      await meshClient.identitySetLabel(draft.trim());
      editing = false;
    } catch (e) {
      saveError = String(e);
    } finally {
      saving = false;
    }
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === "Enter") {
      e.preventDefault();
      void save();
    } else if (e.key === "Escape") {
      e.preventDefault();
      cancelEditing();
    }
  }

  /** Svelte action: focuses the bound element when it mounts.
   *  Lets the inline edit input grab focus on open without using
   *  the static `autofocus` attribute (which Svelte's a11y rules
   *  flag — `autofocus` on initial render disorients screen-reader
   *  users; firing focus from a user-triggered swap is fine). */
  function focusOnMount(node: HTMLInputElement) {
    node.focus();
    node.select();
  }

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
    } catch (e) {
      console.warn("clipboard write failed:", e);
    }
  }
</script>

<div class="content">
  <h3>Device identity</h3>

  {#if meshClient.identity}
    <div class="card">
      <dl class="grid">
        <dt>Label</dt>
        <dd>
          {#if editing}
            <input
              class="label-input"
              type="text"
              maxlength="128"
              placeholder="e.g. laptop, kitchen-pi"
              bind:value={draft}
              onkeydown={onKeydown}
              disabled={saving}
              use:focusOnMount
            />
            <button class="copy" onclick={save} disabled={saving}>
              {saving ? "Saving…" : "Save"}
            </button>
            <button class="copy" onclick={cancelEditing} disabled={saving}>
              Cancel
            </button>
          {:else}
            <span class="label-view">{meshClient.identity.label || "—"}</span>
            <button class="copy" onclick={startEditing}>Edit</button>
          {/if}
        </dd>
        {#if saveError}
          <dt></dt>
          <dd class="err">{saveError}</dd>
        {/if}
        <dt>Device ID</dt>
        <dd class="mono break">
          {meshClient.identity.device_id}
          <button class="copy" onclick={() => copy(meshClient.identity!.device_id)}>
            Copy
          </button>
        </dd>
        <dt>Public key</dt>
        <dd class="mono break">
          {meshClient.identity.pubkey}
          <button class="copy" onclick={() => copy(meshClient.identity!.pubkey)}>
            Copy
          </button>
        </dd>
      </dl>
    </div>

    <h3 class="sub">Daemon</h3>
    {#if meshClient.status}
      <div class="card">
        <dl class="grid">
          <dt>Version</dt>
          <dd class="mono">{meshClient.status.version}</dd>
          <dt>Joined networks</dt>
          <dd>{meshClient.status.joined_networks.length}</dd>
        </dl>
      </div>
    {:else}
      <div class="hint">Daemon status unavailable.</div>
    {/if}

    <p class="hint">
      Identity is persisted at
      <code>~/.myownmesh/.secrets/identity.json</code>. Don't share the file
      with anyone — its private half signs every handshake on this device's
      behalf.
    </p>
  {:else}
    <div class="hint">No identity loaded yet.</div>
  {/if}
</div>

<style>
  .content {
    flex: 1;
    overflow-y: auto;
    padding: 1rem 1.25rem;
    max-width: 50rem;
  }
  h3 {
    margin: 0 0 0.6rem 0;
    font-size: 0.92rem;
    font-weight: 600;
    color: #e8e8e8;
  }
  h3.sub {
    margin-top: 1.4rem;
  }
  .card {
    background: #131318;
    border: 1px solid #1e1e25;
    border-radius: 8px;
    padding: 0.85rem 1rem;
  }
  .grid {
    display: grid;
    grid-template-columns: 9rem 1fr;
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
    gap: 0.5rem;
  }
  .mono {
    font-family: ui-monospace, SFMono-Regular, monospace;
    font-size: 0.78rem;
  }
  .break {
    word-break: break-all;
  }
  .copy {
    background: #1a1a22;
    border: 1px solid #2a2a35;
    border-radius: 4px;
    color: #aaa;
    cursor: pointer;
    font: inherit;
    font-size: 0.7rem;
    padding: 0.15rem 0.5rem;
    flex-shrink: 0;
  }
  .copy:hover {
    border-color: #4a4a55;
    color: #e8e8e8;
  }
  .copy:disabled {
    opacity: 0.5;
    cursor: default;
  }
  .label-view {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .label-input {
    flex: 1;
    min-width: 0;
    background: #0d0d12;
    border: 1px solid #2a2a35;
    border-radius: 4px;
    color: #e8e8e8;
    font: inherit;
    font-size: 0.82rem;
    padding: 0.25rem 0.45rem;
  }
  .label-input:focus {
    outline: none;
    border-color: #6e6ef7;
  }
  .err {
    color: #ffb4b4;
    font-size: 0.72rem;
    font-family: ui-monospace, SFMono-Regular, monospace;
  }
  .hint {
    color: #888;
    font-size: 0.8rem;
    line-height: 1.6;
    margin-top: 1rem;
    max-width: 36rem;
  }
</style>
