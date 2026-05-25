<script lang="ts">
  import { meshClient } from "../mesh-client.svelte";

  // Hamburger and gear both open Settings — keeping both gives the
  // user two equally-discoverable affordances (hamburger reads as
  // "menu" to most users, gear as "preferences"). The sidebar isn't
  // hideable: networks belong in the navigation column at all times,
  // so a toggle would just give the user a worse view of their own
  // setup. Daemon-connection health is surfaced on the empty canvas
  // and in the Activity tab — not as a header pill, which kept
  // reading as "online with peers" to people opening the app for
  // the first time.
  const {
    onOpenSettings,
    onOpenIdentity,
  }: {
    /** Hamburger + gear — opens the Settings panel on its default
     *  tab (Approvals, since that's the most likely first action). */
    onOpenSettings: () => void;
    /** Identity chip — jumps straight to the Identity tab so the
     *  user lands where the rendered chip's label / device id lives. */
    onOpenIdentity: () => void;
  } = $props();

  // Show the bare pubkey + display-suffix that the daemon hands us
  // as `device_id`. It's already truncated for human use; we just
  // chunk it visually for a "shortened fingerprint" feel.
  const idChip = $derived(meshClient.identity?.device_id ?? "—");
</script>

<div class="topbar">
  <button
    class="iconbtn"
    onclick={onOpenSettings}
    aria-label="Settings"
    title="Settings"
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

  <div class="spacer"></div>

  {#if meshClient.identity}
    <button
      class="id-chip"
      onclick={onOpenIdentity}
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
