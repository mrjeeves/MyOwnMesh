<script lang="ts">
  import { meshClient } from "../../mesh-client.svelte";

  // Optional filter by level — defaults to "info+" so debug noise
  // stays hidden until the user opts in.
  let minLevel = $state<"debug" | "info" | "warn" | "error">("info");
  const ORDER: Record<string, number> = {
    debug: 0,
    info: 1,
    warn: 2,
    error: 3,
  };

  const visible = $derived(
    meshClient.diags.filter(
      (d) => (ORDER[d.level] ?? 0) >= (ORDER[minLevel] ?? 0),
    ),
  );

  function fmtTime(): string {
    // The diag entry itself doesn't include a timestamp on the wire
    // (the engine writes through tracing's structured fields, which
    // we don't surface here). The arrival order is the best ordinal
    // we have. Render an empty cell rather than fake "now" — it
    // would mislead during scroll-back of a long log.
    return "";
  }
</script>

<div class="content">
  <div class="head">
    <h3>Activity</h3>
    <div class="filter">
      <label for="lvl">Min level</label>
      <select id="lvl" bind:value={minLevel}>
        <option value="debug">Debug</option>
        <option value="info">Info</option>
        <option value="warn">Warn</option>
        <option value="error">Error</option>
      </select>
    </div>
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

  <div class="log">
    {#if visible.length === 0}
      <div class="empty">No entries.</div>
    {:else}
      {#each visible as d, i (i)}
        <div class="row" data-level={d.level}>
          <span class="lvl">{d.level}</span>
          <span class="cat">{d.category}</span>
          <span class="net mono">{d.network_id}</span>
          <span class="msg">{d.message}</span>
        </div>
      {/each}
    {/if}
  </div>
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
  }
  h3 {
    margin: 0;
    font-size: 0.92rem;
    font-weight: 600;
    color: #e8e8e8;
  }
  .filter {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.8rem;
    color: #888;
  }
  .filter select {
    background: #131318;
    color: #e8e8e8;
    border: 1px solid #2a2a30;
    border-radius: 5px;
    padding: 0.25rem 0.5rem;
    font: inherit;
    font-size: 0.78rem;
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
  .log {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    background: #0d0d12;
    border: 1px solid #1e1e25;
    border-radius: 6px;
    padding: 0.4rem 0;
    font-size: 0.78rem;
    font-family: ui-monospace, SFMono-Regular, monospace;
  }
  .empty {
    color: #555;
    padding: 1rem;
    font-style: italic;
  }
  .row {
    display: grid;
    grid-template-columns: 4rem 7rem 10rem 1fr;
    gap: 0.6rem;
    padding: 0.25rem 0.85rem;
    border-bottom: 1px solid #15151a;
    align-items: baseline;
  }
  .row:last-child {
    border-bottom: none;
  }
  .lvl {
    text-transform: uppercase;
    font-size: 0.65rem;
    letter-spacing: 0.05em;
    color: #888;
  }
  .row[data-level="warn"] .lvl {
    color: #fbbf24;
  }
  .row[data-level="error"] .lvl {
    color: #fca5a5;
  }
  .cat {
    color: #b8b8ff;
    font-size: 0.72rem;
  }
  .net {
    color: #666;
    font-size: 0.7rem;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .msg {
    color: #e0e0e0;
    word-break: break-word;
  }
  .mono {
    font-family: ui-monospace, SFMono-Regular, monospace;
  }
</style>
