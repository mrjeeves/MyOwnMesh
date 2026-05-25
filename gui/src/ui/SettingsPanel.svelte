<script lang="ts">
  import ApprovalsSection from "./settings/ApprovalsSection.svelte";
  import NetworksSection from "./settings/NetworksSection.svelte";
  import IdentitySection from "./settings/IdentitySection.svelte";
  import DiagnosticsSection from "./settings/DiagnosticsSection.svelte";

  /** Approvals lives first because that's the first thing a new
   *  user needs to do — every cross-device peering starts with a
   *  pending approval. Connections (under Networks) is for
   *  already-approved peers; Identity / Diagnostics are
   *  housekeeping. */
  type Tab = "approvals" | "networks" | "identity" | "diagnostics";

  const {
    initialTab = "approvals",
    focusedConfigId,
    onClose,
  }: {
    initialTab?: Tab;
    focusedConfigId: string | null;
    onClose: () => void;
  } = $props();

  // svelte-ignore state_referenced_locally
  let active = $state<Tab>(initialTab);

  const tabs: Array<{ id: Tab; label: string }> = [
    { id: "approvals", label: "Approvals" },
    { id: "networks", label: "Networks" },
    { id: "identity", label: "Identity" },
    { id: "diagnostics", label: "Activity" },
  ];
</script>

<div class="panel" role="dialog" aria-label="Settings">
  <div class="panel-header">
    <button class="back" onclick={onClose} aria-label="Back" title="Back">
      <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true">
        <path
          fill="none"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
          stroke-linejoin="round"
          d="M15 18l-6-6 6-6"
        />
      </svg>
    </button>
    <h2>Settings</h2>
    <button class="close" onclick={onClose} aria-label="Close">✕</button>
  </div>

  <div class="body">
    <nav class="v-tabs" aria-label="Settings sections">
      {#each tabs as t}
        <button
          class="v-tab"
          class:active={active === t.id}
          onclick={() => (active = t.id)}
        >
          <span class="tab-label">{t.label}</span>
        </button>
      {/each}
    </nav>

    <div class="content">
      {#if active === "approvals"}
        <ApprovalsSection />
      {:else if active === "networks"}
        <NetworksSection {focusedConfigId} />
      {:else if active === "identity"}
        <IdentitySection />
      {:else if active === "diagnostics"}
        <DiagnosticsSection />
      {/if}
    </div>
  </div>
</div>

<style>
  .panel {
    position: fixed;
    inset: 0;
    width: 100vw;
    height: 100vh;
    background: #111;
    z-index: 41;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .panel-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.6rem 0.85rem;
    border-bottom: 1px solid #1e1e1e;
    flex-shrink: 0;
  }
  h2 {
    flex: 1;
    margin: 0;
    font-size: 0.95rem;
    font-weight: 600;
  }
  .back,
  .close {
    background: none;
    border: none;
    color: #aaa;
    cursor: pointer;
    padding: 0.3rem 0.4rem;
    border-radius: 4px;
    display: inline-flex;
    align-items: center;
    line-height: 0;
    transition:
      color 0.12s,
      background 0.12s;
  }
  .close {
    color: #888;
    font-size: 1rem;
  }
  .back:hover,
  .close:hover {
    color: #e8e8e8;
    background: #1a1a1a;
  }
  .body {
    flex: 1;
    display: flex;
    min-height: 0;
  }
  .v-tabs {
    width: 180px;
    border-right: 1px solid #1e1e1e;
    background: #0d0d0d;
    display: flex;
    flex-direction: column;
    padding: 0.5rem 0.35rem;
    gap: 0.15rem;
    flex-shrink: 0;
  }
  .v-tab {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    text-align: left;
    background: none;
    border: none;
    color: #888;
    font-size: 0.85rem;
    cursor: pointer;
    padding: 0.5rem 0.65rem;
    border-radius: 6px;
    border-left: 2px solid transparent;
  }
  .v-tab:hover {
    background: #161616;
    color: #ccc;
  }
  .v-tab.active {
    color: #e8e8e8;
    background: #1a1a2a;
    border-left-color: #6e6ef7;
  }
  .tab-label {
    flex: 1;
    min-width: 0;
  }
  .content {
    flex: 1;
    min-width: 0;
    min-height: 0;
    display: flex;
    flex-direction: column;
  }
</style>
