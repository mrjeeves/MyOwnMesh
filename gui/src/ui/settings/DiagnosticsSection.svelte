<script lang="ts">
  /** Activity tab — ring-buffered diagnostic log streamed from the
   *  daemon. Mirrors MyOwnLLM's CloudMeshActivity: every state
   *  transition the engine considers user-relevant lands here as it
   *  happens, newest at the top, capped to a reasonable backlog.
   *
   *  The quiet toggle suppresses info-level chatter (steady-state
   *  peer events, phase transitions); warn and error always land
   *  so genuine problems never get hidden. */

  import { meshClient } from "../../mesh-client.svelte";

  let quiet = $state(false);

  const visible = $derived(
    quiet ? meshClient.diags.filter((d) => d.level !== "info" && d.level !== "debug") : meshClient.diags,
  );

  function diagTime(ts: number): string {
    if (!ts) return "";
    const d = new Date(ts);
    const pad = (n: number) => String(n).padStart(2, "0");
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }
</script>

<div class="content">
  <div class="head">
    <h3>Activity</h3>
    <label
      class="quiet-toggle"
      title="Suppress info-level chatter (steady-state peer events, phase transitions). Warnings and errors always land."
    >
      <input type="checkbox" bind:checked={quiet} />
      quiet logs
    </label>
  </div>

  {#if meshClient.connected !== "live"}
    <div class="banner">
      <div>
        Event stream is <strong>{meshClient.connected}</strong>. Diagnostics will
        populate once the daemon is reachable.
      </div>
      {#if meshClient.lastError}
        <div class="banner-err">{meshClient.lastError}</div>
        {#if meshClient.lastError.includes("couldn't find") || meshClient.lastError.includes("daemon auto-spawn failed")}
          <div class="banner-hint">
            Try: <code>cargo build -p myownmesh</code> from the repo root, or
            set the <code>MYOWNMESH_BIN</code> env var to the daemon binary
            path before launching the GUI.
          </div>
        {/if}
      {/if}
    </div>
  {/if}

  {#if visible.length === 0}
    <div class="empty-state">
      Nothing yet. Mesh activity (peer discovery, handshakes, ICE
      transitions, errors) streams here as it happens. Useful when
      debugging "why isn't this peer showing up"; toggle Quiet to
      suppress steady-state info chatter.
    </div>
  {:else}
    <div class="diag-log" role="log" aria-live="polite">
      {#each visible as d, i (d.ts + ":" + i)}
        <div class="diag-row" data-level={d.level}>
          <span class="diag-time">{diagTime(d.ts)}</span>
          <span class="diag-level">{d.level}</span>
          <span class="diag-cat">{d.category}</span>
          <span class="diag-msg">{d.message}</span>
        </div>
      {/each}
    </div>
    <div class="diag-hint">
      Newest at top. Up to 200 entries — older events roll off as
      new ones arrive.
    </div>
  {/if}
</div>

<style>
  .content {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-height: 0;
    padding: 1rem 1.25rem;
  }
  .head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.75rem;
    flex-shrink: 0;
    gap: 0.55rem;
  }
  h3 {
    margin: 0;
    font-size: 0.92rem;
    font-weight: 600;
    color: #e8e8e8;
  }
  .quiet-toggle {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    font-size: 0.78rem;
    color: #888;
    text-transform: lowercase;
    letter-spacing: 0.04em;
    cursor: pointer;
  }
  .quiet-toggle input[type="checkbox"] {
    accent-color: #6e6ef7;
    margin: 0;
  }
  .banner {
    background: #2a200c;
    border: 1px solid #4a3a14;
    color: #fbbf24;
    border-radius: 6px;
    padding: 0.5rem 0.7rem;
    font-size: 0.8rem;
    margin-bottom: 0.75rem;
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
  }
  .banner-err {
    color: #ffb4b4;
    background: #3a1717;
    border: 1px solid #5a2424;
    padding: 0.35rem 0.55rem;
    border-radius: 4px;
    font-family: ui-monospace, SFMono-Regular, monospace;
    font-size: 0.75rem;
    word-break: break-all;
  }
  .banner-hint {
    color: #cfcfcf;
    font-size: 0.75rem;
    line-height: 1.45;
  }
  .empty-state {
    padding: 0.85rem 1rem;
    border-radius: 7px;
    background: #131318;
    border: 1px dashed #1e1e25;
    color: #888;
    font-size: 0.78rem;
    line-height: 1.55;
    max-width: 40rem;
  }
  .diag-log {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    background: #0d0d12;
    border: 1px solid #1e1e25;
    border-radius: 6px;
    padding: 0.3rem 0.4rem;
    display: flex;
    flex-direction: column;
    gap: 0.05rem;
  }
  .diag-row {
    display: grid;
    grid-template-columns: 4.5rem 3rem 5rem 1fr;
    gap: 0.5rem;
    align-items: baseline;
    font-family: ui-monospace, SFMono-Regular, monospace;
    font-size: 0.72rem;
    color: #cfcfcf;
    padding: 0.18rem 0.35rem;
    border-radius: 3px;
  }
  .diag-row:hover {
    background: #15151c;
  }
  .diag-row[data-level="warn"] {
    color: #fbbf24;
  }
  .diag-row[data-level="error"] {
    color: #fca5a5;
  }
  .diag-time {
    color: #555;
  }
  .diag-level {
    text-transform: uppercase;
    font-size: 0.62rem;
    color: #666;
    letter-spacing: 0.05em;
  }
  .diag-row[data-level="warn"] .diag-level {
    color: #a88d4a;
  }
  .diag-row[data-level="error"] .diag-level {
    color: #c66;
  }
  .diag-cat {
    color: #8b8bff;
    font-size: 0.68rem;
  }
  .diag-msg {
    word-break: break-word;
  }
  .diag-hint {
    font-size: 0.7rem;
    color: #555;
    margin-top: 0.35rem;
    font-style: italic;
  }
</style>
