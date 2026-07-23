<script lang="ts">
  /** Settings → Updates. Surfaces the daemon's self-updater: current
   *  version, the auto-update policy, and — the white-labelling hook — an
   *  editable release-feed URL so a vendor can point this build at their
   *  own release host without rebuilding.
   *
   *  The daemon owns the actual check / stage / apply (it's the process
   *  whose binary gets swapped; the GUI is updated in lockstep beside it),
   *  so everything here is a thin pass-through to `update_*` commands. */

  import { meshClient } from "../../mesh-client.svelte";
  import type { UpdateStatus, UpdateCheckOutcome, UpdatePrefs } from "../../types";

  let status = $state<UpdateStatus | null>(null);
  let loadError = $state<string | null>(null);
  let busy = $state(false);
  let actionError = $state<string | null>(null);
  let outcome = $state<UpdateCheckOutcome | null>(null);

  // Editable drafts for the text/number inputs (the toggles + selects
  // apply on change). Seeded from status whenever we (re)load it.
  let urlDraft = $state("");
  let intervalDraft = $state(6);

  // ---- Danger Zone ----
  // Two-click arming so a reset can't fire on a stray click. When an action
  // fires it reboots the whole stack (the mesh daemon and the app): the daemon
  // is the real datastore, so every layer has to reload from the now-clean disk
  // or an in-memory cache would just re-persist ("resurrect") what we deleted.
  let armed = $state<null | "forget" | "factory">(null);
  let resetting = $state<null | "forget" | "factory">(null);
  let resetError = $state<string | null>(null);

  async function runReset(kind: "forget" | "factory") {
    if (armed !== kind) {
      armed = kind; // first click arms; a second confirms
      return;
    }
    armed = null;
    resetting = kind;
    resetError = null;
    try {
      if (kind === "forget") await meshClient.forgetAllNetworksAndRestart();
      else await meshClient.factoryResetAndRestart();
      // The app relaunches on success, so control doesn't normally return here.
    } catch (e) {
      resetError = String(e);
      resetting = null;
    }
  }

  async function load() {
    try {
      status = await meshClient.updateStatus();
      loadError = null;
      urlDraft = status.release_url;
      intervalDraft = status.check_interval_hours;
    } catch (e) {
      loadError = String(e);
    }
  }

  $effect(() => {
    void load();
  });

  /** Apply a partial prefs edit, swap in the returned status, and reseed
   *  the drafts so the UI reflects what the daemon actually stored. */
  async function applyPrefs(prefs: UpdatePrefs) {
    if (busy) return;
    busy = true;
    actionError = null;
    try {
      status = await meshClient.updateSetPrefs(prefs);
      urlDraft = status.release_url;
      intervalDraft = status.check_interval_hours;
    } catch (e) {
      actionError = String(e);
    } finally {
      busy = false;
    }
  }

  async function checkNow() {
    if (busy) return;
    busy = true;
    actionError = null;
    outcome = null;
    try {
      outcome = await meshClient.updateCheck();
      await load();
    } catch (e) {
      actionError = String(e);
    } finally {
      busy = false;
    }
  }

  async function applyStaged() {
    if (busy) return;
    busy = true;
    actionError = null;
    try {
      await meshClient.updateApply();
      await load();
    } catch (e) {
      actionError = String(e);
    } finally {
      busy = false;
    }
  }

  const urlKey = $derived(status?.channel === "beta" ? "beta_url" : "stable_url");

  async function saveUrl() {
    await applyPrefs({ [urlKey]: urlDraft.trim() });
  }
  async function resetUrl() {
    await applyPrefs({ [urlKey]: "" });
  }

  function fmtLastCheck(ts: number | null): string {
    if (!ts) return "never";
    return new Date(ts * 1000).toLocaleString();
  }

  function outcomeMessage(o: UpdateCheckOutcome): string {
    switch (o.outcome) {
      case "disabled":
        return "Automatic updates are turned off.";
      case "package_manager":
        return "Installed via a package manager — updates are handled by the OS.";
      case "not_due":
        return "Checked recently; nothing to do.";
      case "up_to_date":
        return `Up to date — running the latest release (${o.latest}).`;
      case "policy_blocked":
        return `Version ${o.latest} is available but your auto-apply policy (${o.policy}) won't take that jump automatically. Choose a wider policy or apply it manually.`;
      case "staged":
        return `Version ${o.version} downloaded and staged — apply it below to finish.`;
    }
  }

  const isPackaged = $derived(status?.install_kind === "package_manager");
</script>

<div class="section">
  {#if loadError}
    <div class="err">⚠ Couldn't reach the updater: {loadError}</div>
  {:else if !status}
    <div class="muted">Loading update status…</div>
  {:else}
    <!-- Version + check-now header -->
    <div class="card head-card">
      <div class="head-left">
        <div class="ver">
          <span class="ver-label">MyOwnMesh</span>
          <span class="ver-num">{status.current_version}</span>
          <span class="chan-badge">{status.channel}</span>
        </div>
        <div class="sub">
          Last checked: {fmtLastCheck(status.last_check_at)}
        </div>
      </div>
      <button class="btn" disabled={busy || isPackaged} onclick={checkNow}>
        {busy ? "Checking…" : "Check for updates"}
      </button>
    </div>

    {#if actionError}
      <div class="err">⚠ {actionError}</div>
    {/if}

    {#if isPackaged}
      <div class="banner warn">
        This build was installed by a package manager (Homebrew, apt, MSI,
        …). Self-update is disabled — update through the same tool you
        installed with so versioning stays consistent.
      </div>
    {/if}

    {#if outcome}
      <div class="banner info">{outcomeMessage(outcome)}</div>
    {/if}

    <!-- Staged update -->
    {#if status.staged_version}
      <div class="banner staged">
        <div>
          <strong>Version {status.staged_version} is staged.</strong>
          It applies automatically the next time the daemon restarts, or
          you can finish now.
        </div>
        <button class="btn primary" disabled={busy} onclick={applyStaged}>
          {busy ? "Applying…" : "Apply now"}
        </button>
      </div>
    {/if}

    <!-- Auto-update toggle -->
    <div class="card">
      <label class="toggle">
        <input
          type="checkbox"
          checked={status.enabled}
          disabled={busy || isPackaged}
          onchange={(e) =>
            applyPrefs({ enabled: (e.currentTarget as HTMLInputElement).checked })}
        />
        <span>
          <strong>Automatic updates</strong>
          <span class="muted-inline">
            — the daemon checks the release feed every
            {status.check_interval_hours} h and stages new versions in the
            background.
          </span>
        </span>
      </label>
    </div>

    <!-- Policy -->
    <div class="card">
      <div class="card-title">Update policy</div>
      <div class="grid">
        <label class="field">
          <span class="field-label">Channel</span>
          <select
            value={status.channel}
            disabled={busy}
            onchange={(e) =>
              applyPrefs({ channel: (e.currentTarget as HTMLSelectElement).value })}
          >
            <option value="stable">Stable — latest released version</option>
            <option value="beta">Beta — pre-releases</option>
          </select>
        </label>

        <label class="field">
          <span class="field-label">Auto-apply</span>
          <select
            value={status.auto_apply}
            disabled={busy}
            onchange={(e) =>
              applyPrefs({ auto_apply: (e.currentTarget as HTMLSelectElement).value })}
          >
            <option value="patch">Patch only (0.2.0 → 0.2.1)</option>
            <option value="minor">Patch + minor (0.2.0 → 0.3.0)</option>
            <option value="all">Any version</option>
            <option value="none">Never — stage only, apply manually</option>
          </select>
        </label>

        <label class="field">
          <span class="field-label">Check interval (hours)</span>
          <div class="inline">
            <input
              type="number"
              min="1"
              bind:value={intervalDraft}
              disabled={busy}
            />
            <button
              class="btn small"
              disabled={busy || intervalDraft === status.check_interval_hours}
              onclick={() =>
                applyPrefs({ check_interval_hours: Math.max(1, intervalDraft) })}
            >
              Save
            </button>
          </div>
        </label>
      </div>
    </div>

    <!-- Release feed (white-label) -->
    <div class="card">
      <div class="card-title">
        Release feed
        {#if status.release_url_overridden}
          <span class="custom-badge">custom</span>
        {/if}
      </div>
      <div class="hint subtle">
        Where {status.channel === "beta" ? "beta" : "stable"} releases are
        fetched from. Point this at your own release host to white-label
        the app for your fleet; clear it to fall back to the project
        default. The feed is a GitHub-releases-shaped JSON endpoint.
      </div>
      <div class="add-row">
        <input
          type="text"
          class="mono"
          placeholder="https://api.github.com/repos/you/yourfork/releases/latest"
          bind:value={urlDraft}
          disabled={busy}
        />
        <button
          class="btn small"
          disabled={busy || urlDraft.trim() === status.release_url}
          onclick={saveUrl}
        >
          Save
        </button>
        {#if status.release_url_overridden}
          <button class="btn small ghost" disabled={busy} onclick={resetUrl}>
            Reset
          </button>
        {/if}
      </div>
    </div>
  {/if}

  <!-- Danger Zone — always shown (even if update status failed to load), since
       resets are how you recover a wedged node. Each action reboots the daemon
       + app so state genuinely flushes. -->
  <section class="danger">
    <div class="danger-head">⚠ Danger Zone</div>
    <p class="danger-lead">
      Each of these clears state and then <b>restarts the app and the mesh
      daemon</b>, so every layer reloads from disk. Without the reboot, cached
      state can quietly reappear.
    </p>

    <div class="danger-row">
      <div class="danger-copy">
        <div class="danger-title">Forget all meshes</div>
        <div class="danger-desc">
          Leave and delete every network — rosters and signed governance state —
          while keeping this device's identity. Use when memberships are stuck
          or you want a clean networking slate.
        </div>
      </div>
      <button
        class="danger-btn"
        class:armed={armed === "forget"}
        disabled={resetting !== null}
        onclick={() => runReset("forget")}
      >
        {resetting === "forget"
          ? "Restarting…"
          : armed === "forget"
            ? "Confirm — reboots"
            : "Forget all"}
      </button>
    </div>

    <div class="danger-row">
      <div class="danger-copy">
        <div class="danger-title">Factory reset</div>
        <div class="danger-desc">
          Erase <b>everything</b> — identity, config, and every network. This
          device becomes brand-new to all peers. There is no undo.
        </div>
      </div>
      <button
        class="danger-btn nuke"
        class:armed={armed === "factory"}
        disabled={resetting !== null}
        onclick={() => runReset("factory")}
      >
        {resetting === "factory"
          ? "Resetting…"
          : armed === "factory"
            ? "Confirm wipe — reboots"
            : "Factory reset"}
      </button>
    </div>

    {#if armed}
      <button class="danger-cancel" onclick={() => (armed = null)}>Cancel</button>
    {/if}
    {#if resetError}
      <p class="danger-err">Reset failed: {resetError}</p>
    {/if}
  </section>
</div>

<style>
  .section {
    display: flex;
    flex-direction: column;
    gap: 0.7rem;
    padding: 1rem;
    overflow-y: auto;
  }
  .card {
    background: #131318;
    border: 1px solid #1e1e25;
    border-radius: 8px;
    padding: 0.8rem 1rem;
  }
  .head-card {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    flex-wrap: wrap;
  }
  .ver {
    display: flex;
    align-items: baseline;
    gap: 0.5rem;
  }
  .ver-label {
    color: #888;
    font-size: 0.85rem;
  }
  .ver-num {
    font-weight: 700;
    font-size: 1.05rem;
    color: #e8e8e8;
    font-variant-numeric: tabular-nums;
  }
  .chan-badge {
    font-size: 0.62rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #b8b8ff;
    background: #1a1a2a;
    border: 1px solid #2a2a45;
    border-radius: 999px;
    padding: 0.05rem 0.45rem;
  }
  .sub {
    color: #777;
    font-size: 0.74rem;
    margin-top: 0.25rem;
  }
  .card-title {
    font-weight: 600;
    font-size: 0.82rem;
    margin-bottom: 0.6rem;
    color: #ccc;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .custom-badge {
    font-size: 0.6rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #fbbf24;
    background: #2a200c;
    border: 1px solid #4a3a14;
    border-radius: 999px;
    padding: 0.05rem 0.4rem;
  }
  .grid {
    display: grid;
    gap: 0.7rem;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    font-size: 0.82rem;
  }
  .field-label {
    color: #888;
    font-size: 0.74rem;
  }
  select,
  input[type="text"],
  input[type="number"] {
    background: #0d0d12;
    border: 1px solid #2a2a35;
    color: #e8e8e8;
    padding: 0.35rem 0.55rem;
    border-radius: 5px;
    font: inherit;
    font-size: 0.82rem;
  }
  select:focus,
  input:focus {
    outline: none;
    border-color: #4a4a85;
  }
  input.mono {
    font-family: ui-monospace, SFMono-Regular, monospace;
    font-size: 0.76rem;
  }
  .inline {
    display: flex;
    gap: 0.4rem;
    align-items: center;
  }
  .inline input[type="number"] {
    width: 6rem;
  }
  .add-row {
    display: flex;
    gap: 0.4rem;
    margin-top: 0.4rem;
  }
  .add-row input {
    flex: 1;
    min-width: 0;
  }
  .toggle {
    display: flex;
    align-items: flex-start;
    gap: 0.55rem;
    font-size: 0.84rem;
    cursor: pointer;
  }
  .toggle input {
    margin-top: 0.2rem;
  }
  .muted-inline {
    color: #888;
    font-size: 0.8rem;
  }
  .muted {
    color: #888;
    font-style: italic;
    padding: 1rem;
  }
  .hint.subtle {
    color: #888;
    font-size: 0.76rem;
    line-height: 1.45;
    margin-bottom: 0.2rem;
  }
  .btn {
    padding: 0.45rem 0.95rem;
    border-radius: 5px;
    border: 1px solid #2a2a35;
    background: #1a1a22;
    color: #ccc;
    cursor: pointer;
    font: inherit;
    font-size: 0.82rem;
  }
  .btn:hover:not(:disabled) {
    border-color: #4a4a55;
    color: #e8e8e8;
  }
  .btn.primary {
    background: #2a2a55;
    border-color: #4a4a85;
    color: #e8e8ff;
    font-weight: 500;
  }
  .btn.primary:hover:not(:disabled) {
    background: #3a3a70;
    border-color: #6e6ef7;
  }
  .btn.small {
    padding: 0.3rem 0.7rem;
    font-size: 0.76rem;
  }
  .btn.ghost {
    background: none;
  }
  .btn:disabled {
    opacity: 0.5;
    cursor: default;
  }
  .banner {
    border-radius: 6px;
    padding: 0.6rem 0.8rem;
    font-size: 0.8rem;
    line-height: 1.45;
  }
  .banner.warn {
    background: #2a200c;
    border: 1px solid #4a3a14;
    color: #fbd488;
  }
  .banner.info {
    background: #131820;
    border: 1px solid #1c2630;
    color: #b8c5d0;
  }
  .banner.staged {
    background: #112a1c;
    border: 1px solid #1c4a30;
    color: #b9f5cc;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    flex-wrap: wrap;
  }
  .err {
    background: #3a1717;
    color: #ffb4b4;
    border: 1px solid #5a2424;
    border-radius: 5px;
    padding: 0.45rem 0.6rem;
    font-size: 0.8rem;
  }

  /* ---- Danger Zone ---- */
  .danger {
    margin-top: 1.4rem;
    padding: 0.9rem;
    border: 1px solid #5a2424;
    border-radius: 8px;
    background: #1a1012;
    display: flex;
    flex-direction: column;
    gap: 0.7rem;
  }
  .danger-head {
    color: #ff9b9b;
    font-weight: 700;
    font-size: 0.9rem;
    letter-spacing: 0.02em;
  }
  .danger-lead {
    color: #c9a3a3;
    font-size: 0.78rem;
    margin: 0;
    line-height: 1.4;
  }
  .danger-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.8rem;
    padding-top: 0.6rem;
    border-top: 1px solid #3a2020;
  }
  .danger-copy {
    min-width: 0;
  }
  .danger-title {
    color: #eaeaea;
    font-size: 0.85rem;
    font-weight: 600;
  }
  .danger-desc {
    color: #9a8a8a;
    font-size: 0.76rem;
    line-height: 1.4;
    margin-top: 0.15rem;
  }
  .danger-btn {
    flex: 0 0 auto;
    white-space: nowrap;
    background: #2a1618;
    color: #ffb4b4;
    border: 1px solid #6a2c2c;
    border-radius: 6px;
    padding: 0.4rem 0.7rem;
    font-size: 0.8rem;
    cursor: pointer;
  }
  .danger-btn:hover:not(:disabled) {
    background: #3a1c1e;
  }
  .danger-btn.armed {
    background: #7a1f1f;
    color: #fff;
    border-color: #a33;
    font-weight: 600;
  }
  .danger-btn.nuke.armed {
    background: #9a1010;
  }
  .danger-btn:disabled {
    opacity: 0.6;
    cursor: default;
  }
  .danger-cancel {
    align-self: flex-start;
    background: none;
    border: none;
    color: #888;
    font-size: 0.76rem;
    cursor: pointer;
    text-decoration: underline;
    padding: 0;
  }
  .danger-err {
    color: #ffb4b4;
    background: #3a1717;
    border: 1px solid #5a2424;
    border-radius: 5px;
    padding: 0.45rem 0.6rem;
    font-size: 0.8rem;
    margin: 0;
  }
</style>
