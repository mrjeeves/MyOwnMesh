<script lang="ts">
  /** Edit-network panel — change a saved network's knobs (label,
   *  topology, signaling / STUN / TURN, auto-approve) without hand-editing
   *  `~/.myownmesh/config.json`.
   *
   *  Mechanism: an atomic `networkUpdate`. The daemon hot-applies
   *  label / topology / auto-approve with no peer disruption, and only
   *  restarts the transport for signaling/STUN/TURN edits (the ICE server
   *  set is baked into each connection at creation, so there's no way to
   *  retrofit it live). The roster is preserved either way, and a config
   *  the daemon rejects rolls back to the previous one — so a save can't
   *  strand the network. Embedded in Settings → Networks. */

  import { save as saveDialog } from "@tauri-apps/plugin-dialog";
  import { meshClient } from "../../mesh-client.svelte";
  import { governance } from "../../network-governance.svelte";
  import {
    buildNetworkConfig,
    DEFAULT_NETWORK_SIGNALING,
    DEFAULT_NETWORK_STUN,
    DEFAULT_NETWORK_TURN,
    exportNetworkSettings,
    type TurnEntry,
  } from "../../network-settings";
  import {
    buildTopology,
    topologyHubSet,
    type NetworkConfigInput,
    type NetworkSummary,
    type TopologyKind,
    type TopologyMode,
  } from "../../types";

  const {
    network,
  }: {
    network: NetworkSummary;
  } = $props();

  // ---- editable draft (seeded once per network) -----------------------

  let labelDraft = $state("");
  let topology = $state<TopologyKind>("full_mesh");
  let starHub = $state("");
  let hubsDraft = $state<string[]>([]);
  let hubRedundancy = $state<number | null>(null);
  let hubInput = $state("");
  let signalingDraft = $state<string[]>([]);
  let stunDraft = $state<string[]>([]);
  let turnDraft = $state<TurnEntry[]>([]);
  let turnEntry = $state<TurnEntry>({ url: "", username: "", credential: "" });
  let autoApprove = $state(false);

  let loaded = $state(false);
  let busy = $state(false);
  let actionError = $state<string | null>(null);
  let savedAt = $state<number | null>(null);

  /** Seed the draft from the daemon's current config the first time
   *  we render. Re-seed when the user switches to a different
   *  network — the parent wraps us in a `{#key config_id}` block, so
   *  this `$effect` fires once per mount. */
  $effect(() => {
    if (loaded) return;
    void (async () => {
      try {
        // Roster feeds the hub picker (pick hubs by label, not pubkey).
        void meshClient.refreshRoster(network.config_id);
        const cfg = await meshClient.configShow();
        const net = cfg.networks.find(
          (n: NetworkConfigInput) =>
            n.id === network.config_id || n.network_id === network.network_id,
        );
        if (net) {
          seedFrom(net);
        } else {
          seedDefaults();
        }
        // When a signed TopologyChange owns the shape, the draft edits
        // THAT — the config value underneath is inert until ungoverned.
        const g = governance.governedTopology(network.config_id);
        if (g) seedTopoFrom(g);
      } catch (e) {
        actionError = `couldn't load current config: ${String(e)}`;
        seedDefaults();
      } finally {
        loaded = true;
      }
    })();
  });

  function seedTopoFrom(m: TopologyMode) {
    topology = m.kind;
    if (m.kind === "star") starHub = m.hub;
    if (m.kind === "hubs") {
      hubsDraft = [...m.hubs];
      hubRedundancy = m.spoke_redundancy;
    }
  }

  function seedFrom(cfg: NetworkConfigInput) {
    labelDraft = cfg.label ?? "";
    if (cfg.topology) {
      seedTopoFrom(cfg.topology);
    } else {
      topology = "full_mesh";
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
    signalingDraft = [...DEFAULT_NETWORK_SIGNALING];
    stunDraft = [...DEFAULT_NETWORK_STUN];
    turnDraft = DEFAULT_NETWORK_TURN.map((t) => ({ ...t }));
    autoApprove = false;
  }

  // ---- governed topology (owner-signed, network-wide) -----------------
  //
  // Once a ratified TopologyChange owns the shape, the local picker
  // above becomes read-only everywhere (the daemon refuses TopologySet
  // and ignores the config field) and this section is the only writer —
  // owner-gated, signed, and converging on every member via the log.

  const selfPubkey = $derived(meshClient.identity?.pubkey ?? null);
  const govState = $derived(governance.stateFor(network.config_id));
  const governed = $derived(governance.governedTopology(network.config_id));
  const myRole = $derived(
    selfPubkey ? governance.localRole(network.config_id, selfPubkey) : "member",
  );
  const isOwner = $derived(myRole === "owner");
  const isClosed = $derived(govState.kind === "closed");

  /** Roster rows for the hub picker — id + label so the owner picks
   *  hubs by name, not by pasting pubkeys. */
  const rosterRows = $derived(
    meshClient.rostersByNetwork[network.config_id] ?? [],
  );

  let proposeBusy = $state(false);
  let proposeError = $state<string | null>(null);
  let proposedAt = $state<number | null>(null);
  /** Custody code — revealed only after the daemon asks for one. */
  let mfaCode = $state("");
  let needsMfa = $state(false);

  function toggleHub(deviceId: string) {
    hubsDraft = hubsDraft.includes(deviceId)
      ? hubsDraft.filter((h) => h !== deviceId)
      : [...hubsDraft, deviceId];
  }

  function addHubById() {
    const v = hubInput.trim();
    if (!v) return;
    if (!hubsDraft.includes(v)) hubsDraft = [...hubsDraft, v];
    hubInput = "";
  }

  /** Current draft as a TopologyMode — shared by local save and the
   *  governed propose so the two paths can't drift. */
  function draftMode(): TopologyMode {
    return buildTopology(topology, starHub || null, hubsDraft, hubRedundancy);
  }

  async function proposeGoverned() {
    if (proposeBusy) return;
    if (topology === "hubs" && hubsDraft.length === 0) {
      proposeError = "Pick at least one hub device.";
      return;
    }
    proposeBusy = true;
    proposeError = null;
    proposedAt = null;
    const res = await governance.proposeTopology(
      network.config_id,
      draftMode(),
      needsMfa && mfaCode ? mfaCode : undefined,
    );
    proposeBusy = false;
    if (res.ok) {
      proposedAt = Date.now();
      needsMfa = false;
      mfaCode = "";
      return;
    }
    const reason = res.reason ?? "proposal failed";
    if (/custody|mfa|totp|code/i.test(reason) && !needsMfa) {
      needsMfa = true;
      proposeError =
        "This device holds a custody lock for the network — enter the code and propose again.";
    } else {
      proposeError = reason;
    }
  }

  function hubLabel(id: string): string {
    const row = rosterRows.find(
      (r) => id === r.device_id || id.startsWith(`${r.device_id}-`),
    );
    return row?.label ? row.label : `${id.slice(0, 12)}…`;
  }

  function describeGoverned(m: TopologyMode): string {
    switch (m.kind) {
      case "full_mesh":
        return "Full mesh — every pair connects directly.";
      case "ring":
        return `Ring — each node keeps ${m.n_preferred ?? 3} preferred neighbors.`;
      case "star":
        return `Star — everything routes through ${hubLabel(m.hub)}.`;
      case "hubs":
        return (
          `Hub tier — ${m.hubs.map(hubLabel).join(", ")}; ` +
          `each spoke keeps ${m.spoke_redundancy ?? 2} hub link${(m.spoke_redundancy ?? 2) === 1 ? "" : "s"}.`
        );
    }
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

  // ---- save (atomic in-place update) ----------------------------------

  async function save() {
    if (busy) return;
    busy = true;
    actionError = null;
    let newCfg: NetworkConfigInput;
    try {
      // Build the new wire payload, carrying THIS network's existing
      // config id so the daemon edits the same record in place rather
      // than creating a duplicate.
      const topo = buildTopology(topology, starHub || null, hubsDraft, hubRedundancy);
      newCfg = buildNetworkConfig({
        id: network.config_id,
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

    // Atomic update. The daemon hot-applies label / topology /
    // auto-approve in place (no peers dropped) and only restarts the
    // transport for signaling/STUN/TURN edits — and if it rejects the
    // new config it rolls back to the previous one. The roster survives
    // either path, so unlike the old remove + re-add dance a failed save
    // can never strand the network.
    try {
      await meshClient.networkUpdate(newCfg);
      savedAt = Date.now();
    } catch (e) {
      actionError = `Save failed: ${String(e)}`;
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
      // NetworksSection watches `meshClient.networks`; when this
      // config_id disappears it reseeds the picker to another network,
      // so there's nothing to close here.
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
    Saving applies the new config to the daemon in place. Label,
    topology, and auto-approve apply instantly with no disruption;
    changing signaling / STUN / TURN briefly restarts the transport and
    peers reconnect within a few seconds. Your roster (every peer you've
    already approved) is preserved either way.
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
      <div class="card-title">
        Topology
        {#if governed}
          <span class="gov-badge" title="Owner-signed network-wide shape — every member's daemon follows it">
            governed
          </span>
        {/if}
      </div>

      {#if governed && !isOwner}
        <!-- Governed, and we're not the owner: the shape is the
             owner's signed call; nothing here is writable. -->
        <div class="gov-summary">{describeGoverned(governed)}</div>
        <div class="hint subtle">
          The owner signed this shape into the network's governance —
          every member's daemon (this one included) follows it
          automatically, and local topology settings are ignored.
        </div>
      {:else}
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
          <button
            class="topo-btn"
            class:active={topology === "hubs"}
            onclick={() => (topology = "hubs")}
          >
            Hubs
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
        {#if topology === "hubs"}
          <div class="hub-picker">
            <div class="hint subtle">
              Infra hubs full-mesh each other and carry everyone else:
              spokes connect to a couple of them (rendezvous-assigned)
              instead of to every peer, so nobody pays N². Pick the
              always-on boxes — servers, NAS, the office machine.
            </div>
            {#if rosterRows.length > 0}
              {#each rosterRows as row (row.device_id)}
                <label class="checkbox hub-row">
                  <input
                    type="checkbox"
                    checked={hubsDraft.includes(row.device_id)}
                    onchange={() => toggleHub(row.device_id)}
                  />
                  <span>
                    <strong>{row.label || "(unnamed device)"}</strong>
                    <code class="mono muted-inline">
                      {row.device_id.slice(0, 16)}…
                    </code>
                  </span>
                </label>
              {/each}
            {/if}
            {#each hubsDraft.filter((h) => !rosterRows.some((r) => r.device_id === h)) as extra (extra)}
              <div class="list-row">
                <code class="mono row-text">{extra}</code>
                <button class="row-btn danger" onclick={() => toggleHub(extra)}>
                  Remove
                </button>
              </div>
            {/each}
            <div class="add-row">
              <input
                type="text"
                placeholder="add hub by device id (not yet in roster)"
                bind:value={hubInput}
                class="mono"
                onkeydown={(e) => e.key === "Enter" && addHubById()}
              />
              <button class="row-btn" onclick={addHubById}>Add</button>
            </div>
            <label class="field" style="margin-top: 0.5rem">
              <span class="field-label">
                Hub links per spoke (default 2 — survives one hub restart)
              </span>
              <input
                type="number"
                min="1"
                max={Math.max(hubsDraft.length, 1)}
                placeholder="2"
                value={hubRedundancy ?? ""}
                oninput={(e) => {
                  const v = (e.currentTarget as HTMLInputElement).value;
                  hubRedundancy = v === "" ? null : Math.max(1, Number(v));
                }}
              />
            </label>
          </div>
        {/if}

        {#if isClosed && isOwner}
          <div class="gov-cta">
            {#if governed}
              <div class="hint subtle">
                This shape is governed: signing an update converges every
                member's daemon onto it — no per-device setup.
              </div>
            {:else}
              <div class="hint subtle">
                You own this network. Signing the shape makes it
                network-wide: every member's daemon converges onto it
                automatically (headless boxes included) — the per-device
                picker above stops mattering.
              </div>
            {/if}
            {#if needsMfa}
              <label class="field">
                <span class="field-label">Custody code</span>
                <input
                  type="text"
                  placeholder="123 456"
                  bind:value={mfaCode}
                  class="mono"
                />
              </label>
            {/if}
            {#if proposeError}
              <div class="err">⚠ {proposeError}</div>
            {/if}
            {#if proposedAt}
              <div class="ok">
                ✓ signed — members converge as the log gossips to them
              </div>
            {/if}
            <button
              class="btn primary"
              disabled={proposeBusy}
              onclick={proposeGoverned}
            >
              {proposeBusy
                ? "Signing…"
                : governed
                  ? "Sign updated network-wide topology"
                  : "Sign & make network-wide"}
            </button>
          </div>
        {:else if governed && isOwner}
          <!-- governed open-network edge (shouldn't occur: governance
               requires closed) — owner still sees the summary. -->
          <div class="gov-summary">{describeGoverned(governed)}</div>
        {/if}
      {/if}
    </div>

    <!-- Signaling relays -->
    <div class="card">
      <div class="card-title">Signaling relays</div>
      <div class="hint subtle">
        Defaults to the reference relay
        <code>wss://myownmesh.com</code>; leaving the list empty falls
        back to that same built-in default. Add your own WebSocket URLs
        (<code>wss://...</code>) to pin specific relays — they take full
        precedence over the default.
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
        hotspots). New networks default to the shared-guest relay
        <code>turn:turn.myownmesh.com:3478</code> so this works out of
        the box; it's bandwidth-capped, so for sustained throughput
        bring your own (<code>services.turn</code> on any myownmesh
        host, Cloudflare Calls, or self-hosted Coturn).
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
  .gov-badge {
    font-size: 0.64rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #b8b8ff;
    background: #1a1a2a;
    border: 1px solid #4a4a85;
    border-radius: 999px;
    padding: 0.08rem 0.5rem;
  }
  .gov-summary {
    font-size: 0.82rem;
    color: #e8e8e8;
    background: #0d0d12;
    border: 1px solid #2a2a35;
    border-radius: 5px;
    padding: 0.45rem 0.6rem;
    margin-bottom: 0.4rem;
    line-height: 1.45;
  }
  .gov-cta {
    margin-top: 0.7rem;
    padding-top: 0.6rem;
    border-top: 1px solid #1e1e25;
    display: flex;
    flex-direction: column;
    gap: 0.45rem;
    align-items: flex-start;
  }
  .hub-picker {
    margin-top: 0.5rem;
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
  }
  .hub-row code {
    margin-left: 0.4rem;
  }
  input[type="number"] {
    background: #0d0d12;
    border: 1px solid #2a2a35;
    color: #e8e8e8;
    padding: 0.35rem 0.55rem;
    border-radius: 5px;
    font: inherit;
    font-size: 0.82rem;
    width: 8rem;
  }
  input[type="number"]:focus {
    outline: none;
    border-color: #4a4a85;
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
