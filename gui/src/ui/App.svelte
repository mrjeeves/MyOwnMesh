<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { getVersion } from "@tauri-apps/api/app";
  import { getCurrentWindow } from "@tauri-apps/api/window";
  import { meshClient } from "../mesh-client.svelte";
  import TopBar from "./TopBar.svelte";
  import Sidebar from "./Sidebar.svelte";
  import NodeMap from "./NodeMap.svelte";
  import SettingsPanel from "./SettingsPanel.svelte";

  let settingsOpen = $state(false);
  let settingsInitialTab =
    $state<"approvals" | "networks" | "identity" | "diagnostics">("approvals");

  /** The config_id of the network the node-map + sidebar are
   *  currently focused on. `null` means "show the first one we
   *  have", set on first reactive read so a freshly-launched UI
   *  doesn't show a blank canvas while networks load. */
  let focusedConfigId = $state<string | null>(null);

  /** When the user clicks a peer in the sidebar, the node map
   *  highlights it. The selection is reset when the focused
   *  network changes or the peer disappears from the snapshot. */
  let selectedPeerId = $state<string | null>(null);

  $effect(() => {
    // Pick the first network as the default focus once they
    // load. Re-runs when networks arrive / disappear.
    if (!focusedConfigId && meshClient.networks.length > 0) {
      focusedConfigId = meshClient.networks[0].config_id;
    }
    if (
      focusedConfigId &&
      !meshClient.networks.some((n) => n.config_id === focusedConfigId)
    ) {
      focusedConfigId = meshClient.networks[0]?.config_id ?? null;
      selectedPeerId = null;
    }
  });

  const focusedNetwork = $derived(
    meshClient.networks.find((n) => n.config_id === focusedConfigId) ?? null,
  );

  const focusedPeers = $derived(
    focusedNetwork
      ? meshClient.peersByNetwork[focusedNetwork.config_id] ?? []
      : [],
  );

  const focusedRoster = $derived(
    focusedNetwork
      ? meshClient.rostersByNetwork[focusedNetwork.config_id] ?? []
      : [],
  );

  const focusedNetworkChangeTs = $derived(
    focusedNetwork
      ? meshClient.networkChangeTsByNetwork[focusedNetwork.config_id] ?? 0
      : 0,
  );

  /** Open the settings panel on a specific tab. Defaults to
   *  "approvals" because that's where new users go to bring a peer
   *  online for the first time — the most discoverable surface for
   *  the most common first-time question ("how do I connect this
   *  device?"). Other call sites pass an explicit tab when they
   *  know the user wants Networks (sidebar +) or Identity. */
  function openSettings(
    tab: "approvals" | "networks" | "identity" | "diagnostics" = "approvals",
  ) {
    settingsInitialTab = tab;
    settingsOpen = true;
  }

  onMount(() => {
    // Stamp the version into the window title so users can tell at
    // a glance which build they're running (matches MyOwnLLM). The
    // version comes from the Tauri runtime — single source of truth
    // is gui/src-tauri/Cargo.toml, kept in sync by bump-version.sh.
    getVersion()
      .then((v) => {
        getCurrentWindow()
          .setTitle(`MyOwnMesh ${v}`)
          .catch(() => {});
      })
      .catch(() => {});

    meshClient.init().catch((e) => {
      console.error("mesh client init failed:", e);
    });
  });

  onDestroy(() => {
    meshClient.dispose();
  });
</script>

<div class="app">
  <TopBar
    onOpenSettings={() => openSettings("approvals")}
    onOpenIdentity={() => openSettings("identity")}
  />

  <div class="layout">
    <!-- Sidebar is always visible: the networks column is the
         primary navigation surface, hiding it would just degrade
         the view of the user's own setup. Settings (hamburger /
         gear) is where users go for collapse-style actions. -->
    <Sidebar
      focusedConfigId={focusedConfigId}
      selectedPeerId={selectedPeerId}
      onSelectNetwork={(id) => {
        focusedConfigId = id;
        selectedPeerId = null;
      }}
      onSelectPeer={(deviceId) => (selectedPeerId = deviceId)}
      onOpenNetworksSettings={() => openSettings("networks")}
      onOpenNetworkSettings={(id) => {
        // The gear on a network row opens the full Networks settings
        // surface scoped to that network. Focus it on the graph too so
        // the canvas stays relevant to what the user is configuring.
        focusedConfigId = id;
        selectedPeerId = null;
        openSettings("networks");
      }}
    />

    <div class="canvas">
      {#if focusedNetwork}
        <NodeMap
          network={focusedNetwork}
          peers={focusedPeers}
          roster={focusedRoster}
          networkChangeTs={focusedNetworkChangeTs}
          selfDeviceId={meshClient.identity?.pubkey ?? ""}
          selfLabel={meshClient.identity?.label ?? ""}
          selectedPeerId={selectedPeerId}
          onSelectPeer={(id) => (selectedPeerId = id)}
        />
      {:else}
        <div class="empty">
          {#if meshClient.connected === "disconnected"}
            <div class="empty-title">Daemon not reachable</div>
            <div class="empty-sub">
              Start <code>myownmesh serve</code> and the UI will connect
              automatically.
            </div>
            {#if meshClient.lastError}
              <div class="empty-err">{meshClient.lastError}</div>
            {/if}
          {:else if meshClient.networks.length === 0}
            <div class="empty-title">No networks yet</div>
            <div class="empty-sub">
              Use <button class="empty-link" onclick={() => openSettings("networks")}>
                Networks settings
              </button>
              to add or import one — or click the
              <strong>+</strong> button in the sidebar header.
            </div>
          {:else}
            <div class="empty-title">Loading…</div>
          {/if}
        </div>
      {/if}
    </div>
  </div>

  {#if settingsOpen}
    <SettingsPanel
      initialTab={settingsInitialTab}
      focusedConfigId={focusedConfigId}
      onClose={() => (settingsOpen = false)}
    />
  {/if}
</div>

<style>
  :global(*, *::before, *::after) {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
  }
  :global(body) {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: #0f0f0f;
    color: #e8e8e8;
    height: 100vh;
    overflow: hidden;
  }
  :global(*) {
    scrollbar-width: auto;
    scrollbar-color: #6a6a85 #1a1a1a;
  }
  :global(*::-webkit-scrollbar) {
    width: 12px;
    height: 12px;
  }
  :global(*::-webkit-scrollbar-track) {
    background: #1a1a1a;
  }
  :global(*::-webkit-scrollbar-thumb) {
    background: #6a6a85;
    border-radius: 6px;
    border: 1px solid #1a1a1a;
  }
  :global(code) {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    background: #1a1a1a;
    padding: 0.05rem 0.35rem;
    border-radius: 3px;
    font-size: 0.85em;
  }

  .app {
    height: 100vh;
    display: flex;
    flex-direction: column;
  }
  .layout {
    flex: 1;
    display: flex;
    min-height: 0;
  }
  .canvas {
    flex: 1;
    min-width: 0;
    min-height: 0;
    display: flex;
    flex-direction: column;
    background: #0a0a0a;
    /* Anchor for the per-network overlay's absolute positioning so
       it fills the graph area exactly and doesn't bleed under the
       sidebar. */
    position: relative;
  }
  .empty {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    color: #888;
    text-align: center;
    padding: 2rem;
  }
  .empty-title {
    font-size: 1rem;
    color: #ccc;
    font-weight: 600;
  }
  .empty-sub {
    font-size: 0.85rem;
    line-height: 1.5;
    max-width: 30rem;
  }
  .empty-err {
    margin-top: 0.5rem;
    font-size: 0.75rem;
    color: #ffb4b4;
    background: #3a1717;
    border: 1px solid #5a2424;
    padding: 0.35rem 0.6rem;
    border-radius: 4px;
    font-family: ui-monospace, SFMono-Regular, monospace;
    max-width: 40rem;
    word-break: break-all;
  }
  .empty-link {
    background: none;
    border: none;
    color: #8b8bff;
    cursor: pointer;
    font: inherit;
    padding: 0;
    text-decoration: underline;
  }
  .empty-link:hover {
    color: #b9b9ff;
  }
</style>
