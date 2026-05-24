<script lang="ts">
  import { meshClient } from "../mesh-client.svelte";

  const {
    onOpenSettings,
    onToggleSidebar,
  }: {
    onOpenSettings: () => void;
    onToggleSidebar: () => void;
  } = $props();

  // Show the bare pubkey + display-suffix that the daemon hands us
  // as `device_id`. It's already truncated for human use; we just
  // chunk it visually for a "shortened fingerprint" feel.
  const idChip = $derived(meshClient.identity?.device_id ?? "—");

  const phaseLabel = $derived(() => {
    const c = meshClient.connected;
    if (c === "live") return "connected";
    if (c === "disconnected") return "no daemon";
    return "connecting…";
  });

  // Tooltip for the daemon-connection pill — the colored dot + label
  // tracks the GUI's socket to the local `myownmesh` daemon, not the
  // health of any particular mesh network. Spelling it out keeps
  // users from misreading it as "online with peers".
  const phaseTooltip = $derived(() => {
    const c = meshClient.connected;
    if (c === "live") return "Connected to the local myownmesh daemon.";
    if (c === "disconnected")
      return "Can't reach the local myownmesh daemon socket.";
    return "Opening the local myownmesh daemon socket…";
  });
</script>

<div class="topbar">
  <button
    class="iconbtn"
    onclick={onToggleSidebar}
    aria-label="Toggle sidebar"
    title="Toggle sidebar"
  >
    <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true">
      <path
        fill="none"
        stroke="currentColor"
        stroke-width="2"
        stroke-linecap="round"
        d="M4 6h16M4 12h16M4 18h16"
      />
    </svg>
  </button>

  <div class="brand">MyOwnMesh</div>

  <div class="status" data-status={meshClient.connected} title={phaseTooltip()}>
    <span class="dot"></span>
    <span class="status-label">{phaseLabel()}</span>
  </div>

  <div class="spacer"></div>

  {#if meshClient.identity}
    <button
      class="id-chip"
      onclick={onOpenSettings}
      title="Open settings — identity"
    >
      <span class="id-label">{meshClient.identity.label || "device"}</span>
      <span class="id-id">{idChip}</span>
    </button>
  {/if}

  <button
    class="iconbtn"
    onclick={onOpenSettings}
    aria-label="Settings"
    title="Settings"
  >
    <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true">
      <circle cx="12" cy="12" r="3" fill="none" stroke="currentColor" stroke-width="2" />
      <path
        fill="none"
        stroke="currentColor"
        stroke-width="2"
        stroke-linejoin="round"
        d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3h.1a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.9-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8v.1a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"
      />
    </svg>
  </button>
</div>

<style>
  .topbar {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.4rem 0.6rem;
    background: #0d0d0d;
    border-bottom: 1px solid #1e1e1e;
    flex-shrink: 0;
    height: 42px;
  }
  .brand {
    font-size: 0.9rem;
    font-weight: 600;
    letter-spacing: 0.01em;
    color: #e8e8e8;
  }
  .iconbtn {
    background: none;
    border: none;
    color: #aaa;
    cursor: pointer;
    padding: 0.35rem 0.4rem;
    border-radius: 5px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }
  .iconbtn:hover {
    background: #1a1a1a;
    color: #e8e8e8;
  }
  .status {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    font-size: 0.75rem;
    color: #888;
    padding: 0.15rem 0.5rem;
    border-radius: 999px;
    background: #131318;
    border: 1px solid #1e1e25;
  }
  .status .dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: #888;
  }
  .status[data-status="live"] .dot {
    background: #4ade80;
    box-shadow: 0 0 6px rgba(74, 222, 128, 0.6);
  }
  .status[data-status="live"] .status-label {
    color: #b9f5cc;
  }
  .status[data-status="disconnected"] .dot {
    background: #ef4444;
    box-shadow: 0 0 6px rgba(239, 68, 68, 0.6);
  }
  .status[data-status="disconnected"] .status-label {
    color: #fca5a5;
  }
  .status[data-status="connecting"] .dot {
    background: #fbbf24;
    box-shadow: 0 0 6px rgba(251, 191, 36, 0.6);
  }
  .spacer {
    flex: 1;
  }
  .id-chip {
    background: #131320;
    border: 1px solid #2a2a40;
    color: #ccc;
    cursor: pointer;
    padding: 0.25rem 0.6rem;
    border-radius: 999px;
    font-size: 0.72rem;
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  }
  .id-chip:hover {
    border-color: #4a4a70;
    color: #fff;
  }
  .id-label {
    font-weight: 600;
  }
  .id-id {
    font-family: ui-monospace, SFMono-Regular, monospace;
    color: #888;
    font-size: 0.68rem;
    max-width: 12ch;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
</style>
