<script lang="ts">
  import { meshClient } from "../../mesh-client.svelte";
  import type {
    EndpointReport,
    ServicesConfig,
    ServicesReport,
  } from "../../types";

  /** Editable draft of the device's services config. Kept in sync with
   *  the daemon's persisted config until the user edits a field, after
   *  which `dirty` preserves their changes until they Save or Reset. */
  let draft = $state<ServicesConfig | null>(null);
  let dirty = $state(false);
  let saving = $state(false);
  let saveError = $state<string | null>(null);

  // Inputs for adding a new TURN credential.
  let newCredUser = $state("");
  let newCredPass = $state("");

  function clone(c: ServicesConfig): ServicesConfig {
    return structuredClone($state.snapshot(c));
  }

  // Re-sync the draft from the daemon's config whenever it changes and
  // the user hasn't started editing. Once `dirty`, their edits win until
  // they Save (which clears `dirty`, letting the refreshed config flow
  // back in) or Reset.
  $effect(() => {
    const live = meshClient.services?.config;
    if (live && !dirty) {
      draft = clone(live);
    }
  });

  function markDirty() {
    dirty = true;
    saveError = null;
  }

  function reset() {
    const live = meshClient.services?.config;
    if (live) draft = clone(live);
    dirty = false;
    saveError = null;
  }

  function addCredential() {
    if (!draft) return;
    const u = newCredUser.trim();
    const p = newCredPass;
    if (!u || !p) return;
    if (draft.turn.credentials.some((c) => c.username === u)) {
      saveError = `credential for "${u}" already exists`;
      return;
    }
    draft.turn.credentials = [...draft.turn.credentials, { username: u, password: p }];
    newCredUser = "";
    newCredPass = "";
    markDirty();
  }

  function removeCredential(username: string) {
    if (!draft) return;
    draft.turn.credentials = draft.turn.credentials.filter(
      (c) => c.username !== username,
    );
    markDirty();
  }

  async function save() {
    if (!draft || saving) return;
    saving = true;
    saveError = null;
    try {
      await meshClient.servicesSet($state.snapshot(draft));
      dirty = false;
    } catch (e) {
      saveError = String(e);
    } finally {
      saving = false;
    }
  }

  const report = $derived<ServicesReport | null>(meshClient.services?.status ?? null);

  /** A short human status for a listener service, combining the
   *  enabled flag and whether the listener actually came up. */
  function endpointState(r: EndpointReport | undefined): {
    cls: string;
    text: string;
  } {
    if (!r || !r.enabled) return { cls: "off", text: "off" };
    if (r.running) return { cls: "on", text: `running · ${r.listen ?? "?"}` };
    return { cls: "warn", text: "enabled, not running — check config / port" };
  }

  // Per-service status pills. Hoisted to derived values because Svelte
  // only allows {@const} as the immediate child of a block, not inside
  // a plain element.
  // Signaling pill also surfaces the live connection count so an
  // operator can see whether peers are actually reaching the relay.
  const sigState = $derived.by(() => {
    const r = report?.signaling;
    const base = endpointState(r);
    if (r?.running && r.activity) {
      const n = r.activity.connections;
      return { cls: base.cls, text: `${base.text} · ${n} client${n === 1 ? "" : "s"}` };
    }
    return base;
  });
  const stunState = $derived(endpointState(report?.stun));
  const turnState = $derived(endpointState(report?.turn));
</script>

<div class="content">
  <h3>Hosted services</h3>
  <p class="intro">
    This device can be any combination of a mesh node and hosted
    infrastructure — relay, signaling, STUN, TURN. Each service runs in
    the local daemon and is advertised to peers so they can discover and
    adopt it, which is what makes a fully self-hosted, internet-isolated
    network practical.
  </p>

  {#if !draft || !report}
    <div class="hint">
      Couldn't read service status. The daemon may be stopped, or an older
      version that predates service hosting — update or rebuild the daemon
      and reopen this panel.
    </div>
  {:else}
    <!-- Node --------------------------------------------------------- -->
    <div class="card">
      <div class="card-head">
        <label class="toggle">
          <input
            type="checkbox"
            bind:checked={draft.node.enabled}
            onchange={markDirty}
          />
          <span class="svc-name">Mesh node</span>
        </label>
        <span class="status {report.node.enabled ? 'on' : 'off'}">
          {report.node.enabled
            ? `joined ${report.node.joined} network${report.node.joined === 1 ? "" : "s"}`
            : "pure-infrastructure mode"}
        </span>
      </div>
      <p class="svc-hint">
        Whether this device participates as a regular mesh member, joining
        its configured networks. Turn off to run a pure-infrastructure box
        that only hosts the services below — the relay needs node
        participation, so it goes idle when this is off.
      </p>
    </div>

    <!-- Relay --------------------------------------------------------- -->
    <div class="card">
      <div class="card-head">
        <label class="toggle">
          <input
            type="checkbox"
            bind:checked={draft.relay.enabled}
            onchange={markDirty}
          />
          <span class="svc-name">Relay</span>
        </label>
        <span class="status {report.relay.enabled ? 'on' : 'off'}">
          {report.relay.enabled
            ? `routing ${report.relay.networks} network${report.relay.networks === 1 ? "" : "s"}`
            : "off"}
        </span>
      </div>
      <p class="svc-hint">
        Forwards traffic between roster members so peers that can each
        reach this device, but not each other, can still talk — a router /
        ingress / egress hub. Roster-gated on both ends.
      </p>
      {#if draft.relay.enabled}
        <div class="fields">
          <label class="field">
            <span>Max broadcast fan-out</span>
            <input
              type="number"
              min="0"
              bind:value={draft.relay.max_fanout}
              oninput={markDirty}
            />
            <span class="unit">0 = unlimited</span>
          </label>
        </div>
      {/if}
    </div>

    <!-- Signaling ----------------------------------------------------- -->
    <div class="card">
      <div class="card-head">
        <label class="toggle">
          <input
            type="checkbox"
            bind:checked={draft.signaling.enabled}
            onchange={markDirty}
          />
          <span class="svc-name">Signaling relay</span>
        </label>
        <span class="status {sigState.cls}">{sigState.text}</span>
      </div>
      <p class="svc-hint">
        A self-hosted Nostr relay (NIP-01 over WebSocket) peers can use in
        place of public Nostr. Point a network's signaling servers at
        <code>ws://this-host:port</code> — the built-in driver speaks to it
        unchanged.
      </p>
      {#if draft.signaling.enabled}
        <div class="fields">
          <label class="field">
            <span>Bind</span>
            <input
              type="text"
              bind:value={draft.signaling.bind}
              oninput={markDirty}
            />
          </label>
          <label class="field">
            <span>Port</span>
            <input
              type="number"
              min="0"
              max="65535"
              bind:value={draft.signaling.port}
              oninput={markDirty}
            />
          </label>
        </div>

        <div class="creds">
          <div class="creds-title">Flood limits (0 = unlimited)</div>
          <div class="fields">
            <label class="field">
              <span>Events / sec</span>
              <input
                type="number"
                min="0"
                bind:value={draft.signaling.limits.max_event_rate}
                oninput={markDirty}
              />
            </label>
            <label class="field">
              <span>REQ / sec</span>
              <input
                type="number"
                min="0"
                bind:value={draft.signaling.limits.max_req_rate}
                oninput={markDirty}
              />
            </label>
            <label class="field">
              <span>Subscriptions / conn</span>
              <input
                type="number"
                min="0"
                bind:value={draft.signaling.limits.max_subscriptions}
                oninput={markDirty}
              />
            </label>
            <label class="field">
              <span>Connections / IP</span>
              <input
                type="number"
                min="0"
                bind:value={draft.signaling.limits.max_connections_per_ip}
                oninput={markDirty}
              />
            </label>
            <label class="field">
              <span>Max frame bytes</span>
              <input
                type="number"
                min="0"
                bind:value={draft.signaling.limits.max_message_bytes}
                oninput={markDirty}
              />
            </label>
            <label class="field">
              <span>Filters / REQ</span>
              <input
                type="number"
                min="0"
                bind:value={draft.signaling.limits.max_filters_per_req}
                oninput={markDirty}
              />
            </label>
          </div>
        </div>
      {/if}
    </div>

    <!-- STUN ---------------------------------------------------------- -->
    <div class="card">
      <div class="card-head">
        <label class="toggle">
          <input
            type="checkbox"
            bind:checked={draft.stun.enabled}
            onchange={markDirty}
          />
          <span class="svc-name">STUN server</span>
        </label>
        <span class="status {stunState.cls}">{stunState.text}</span>
      </div>
      <p class="svc-hint">
        Answers STUN binding requests so peers learn their reflexive
        address without a public provider. (TURN below also answers STUN,
        so you rarely need both.)
      </p>
      {#if draft.stun.enabled}
        <div class="fields">
          <label class="field">
            <span>Bind</span>
            <input
              type="text"
              bind:value={draft.stun.bind}
              oninput={markDirty}
            />
          </label>
          <label class="field">
            <span>Port</span>
            <input
              type="number"
              min="0"
              max="65535"
              bind:value={draft.stun.port}
              oninput={markDirty}
            />
          </label>
        </div>
      {/if}
    </div>

    <!-- TURN ---------------------------------------------------------- -->
    <div class="card">
      <div class="card-head">
        <label class="toggle">
          <input
            type="checkbox"
            bind:checked={draft.turn.enabled}
            onchange={markDirty}
          />
          <span class="svc-name">TURN server</span>
        </label>
        <span class="status {turnState.cls}">{turnState.text}</span>
      </div>
      <p class="svc-hint">
        Relays media / data for peers behind symmetric NAT. Needs a public
        IP to advertise and at least one credential — mirror a credential
        into each peer's TURN config. Enabled without these, it shows as
        "not running".
      </p>
      {#if draft.turn.enabled}
        <div class="fields">
          <label class="field">
            <span>Bind</span>
            <input
              type="text"
              bind:value={draft.turn.bind}
              oninput={markDirty}
            />
          </label>
          <label class="field">
            <span>Port</span>
            <input
              type="number"
              min="0"
              max="65535"
              bind:value={draft.turn.port}
              oninput={markDirty}
            />
          </label>
          <label class="field wide">
            <span>Public IP</span>
            <input
              type="text"
              placeholder="e.g. 203.0.113.7 — the device's routable address"
              bind:value={draft.turn.public_ip}
              oninput={markDirty}
            />
          </label>
          <label class="field">
            <span>Realm</span>
            <input
              type="text"
              bind:value={draft.turn.realm}
              oninput={markDirty}
            />
          </label>
          <label class="field wide">
            <span>Max bandwidth per connection (bytes/sec, each way)</span>
            <input
              type="number"
              min="0"
              bind:value={draft.turn.max_bps_per_connection}
              oninput={markDirty}
            />
            <span class="unit">0 = unlimited — a global QoS cap on every allocation</span>
          </label>
        </div>

        <div class="creds">
          <div class="creds-title">Credentials</div>
          {#each draft.turn.credentials as c (c.username)}
            <div class="cred-row">
              <code class="cred-user">{c.username}</code>
              <span class="cred-mask">••••••</span>
              <button class="row-btn danger" onclick={() => removeCredential(c.username)}>
                Remove
              </button>
            </div>
          {/each}
          {#if draft.turn.credentials.length === 0}
            <div class="cred-empty">No credentials — TURN won't start.</div>
          {/if}
          <div class="cred-add">
            <input
              type="text"
              placeholder="username"
              bind:value={newCredUser}
              onkeydown={(e) => e.key === "Enter" && addCredential()}
            />
            <input
              type="text"
              placeholder="password"
              bind:value={newCredPass}
              onkeydown={(e) => e.key === "Enter" && addCredential()}
            />
            <button class="row-btn" onclick={addCredential}>Add</button>
          </div>
        </div>
      {/if}
    </div>

    <!-- Save bar ------------------------------------------------------ -->
    <div class="save-bar">
      <button class="save-btn" disabled={!dirty || saving} onclick={save}>
        {saving ? "Applying…" : "Apply changes"}
      </button>
      <button class="reset-btn" disabled={!dirty || saving} onclick={reset}>
        Reset
      </button>
      {#if dirty}
        <span class="dirty-note">unsaved changes</span>
      {/if}
      {#if saveError}
        <span class="err">{saveError}</span>
      {/if}
    </div>

    <p class="hint">
      Services are persisted to <code>~/.myownmesh/config.json</code> and
      restart with the daemon. They're device-level: a hosted service
      serves every network this device joins (and any external client).
    </p>
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
    margin: 0 0 0.4rem 0;
    font-size: 0.92rem;
    font-weight: 600;
    color: #e8e8e8;
  }
  .intro {
    color: #999;
    font-size: 0.8rem;
    line-height: 1.55;
    margin: 0 0 1rem 0;
    max-width: 40rem;
  }
  .card {
    background: #131318;
    border: 1px solid #1e1e25;
    border-radius: 8px;
    padding: 0.85rem 1rem;
    margin-bottom: 0.85rem;
  }
  .card-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.6rem;
  }
  .toggle {
    display: flex;
    align-items: center;
    gap: 0.55rem;
    cursor: pointer;
  }
  .toggle input {
    width: 1rem;
    height: 1rem;
    accent-color: #6e6ef7;
    cursor: pointer;
  }
  .svc-name {
    font-size: 0.9rem;
    font-weight: 600;
    color: #e8e8e8;
  }
  .status {
    font-size: 0.72rem;
    font-family: ui-monospace, SFMono-Regular, monospace;
    padding: 0.1rem 0.45rem;
    border-radius: 999px;
    white-space: nowrap;
  }
  .status.on {
    color: #9ff0c0;
    background: #12321f;
  }
  .status.off {
    color: #777;
    background: #1a1a1f;
  }
  .status.warn {
    color: #ffd79a;
    background: #33260f;
  }
  .svc-hint {
    color: #888;
    font-size: 0.76rem;
    line-height: 1.5;
    margin: 0.5rem 0 0 0;
  }
  .svc-hint code,
  .hint code {
    background: #1a1a22;
    padding: 0.02rem 0.3rem;
    border-radius: 3px;
    font-size: 0.72rem;
  }
  .fields {
    display: flex;
    flex-wrap: wrap;
    gap: 0.6rem 1rem;
    margin-top: 0.75rem;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
    font-size: 0.74rem;
    color: #999;
  }
  .field.wide {
    flex: 1 1 100%;
  }
  .field input {
    background: #0d0d12;
    border: 1px solid #2a2a35;
    border-radius: 4px;
    color: #e8e8e8;
    font: inherit;
    font-size: 0.8rem;
    padding: 0.25rem 0.45rem;
    width: 9rem;
  }
  .field.wide input {
    width: 100%;
  }
  .field input:focus {
    outline: none;
    border-color: #6e6ef7;
  }
  .unit {
    color: #666;
    font-size: 0.68rem;
  }
  .creds {
    margin-top: 0.85rem;
    padding-top: 0.7rem;
    border-top: 1px solid #1e1e25;
  }
  .creds-title {
    font-size: 0.76rem;
    color: #aaa;
    margin-bottom: 0.45rem;
  }
  .cred-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.25rem 0;
  }
  .cred-user {
    font-family: ui-monospace, SFMono-Regular, monospace;
    font-size: 0.78rem;
    color: #e0e0e0;
    flex: 1;
  }
  .cred-mask {
    color: #666;
    font-size: 0.8rem;
    letter-spacing: 1px;
  }
  .cred-empty {
    color: #ffb4b4;
    font-size: 0.72rem;
    padding: 0.2rem 0;
  }
  .cred-add {
    display: flex;
    gap: 0.4rem;
    margin-top: 0.45rem;
  }
  .cred-add input {
    flex: 1;
    background: #0d0d12;
    border: 1px solid #2a2a35;
    border-radius: 4px;
    color: #e8e8e8;
    font: inherit;
    font-size: 0.78rem;
    padding: 0.25rem 0.45rem;
  }
  .cred-add input:focus {
    outline: none;
    border-color: #6e6ef7;
  }
  .row-btn {
    background: #1a1a22;
    border: 1px solid #2a2a35;
    border-radius: 4px;
    color: #aaa;
    cursor: pointer;
    font: inherit;
    font-size: 0.72rem;
    padding: 0.2rem 0.6rem;
    flex-shrink: 0;
  }
  .row-btn:hover {
    border-color: #4a4a55;
    color: #e8e8e8;
  }
  .row-btn.danger:hover {
    border-color: #80303a;
    color: #ffb4b4;
  }
  .save-bar {
    display: flex;
    align-items: center;
    gap: 0.7rem;
    margin: 0.4rem 0 0.6rem 0;
  }
  .save-btn {
    padding: 0.4rem 1rem;
    background: #1a1a2a;
    border: 1px solid #3a3a6a;
    border-radius: 5px;
    color: #c8c8ff;
    cursor: pointer;
    font: inherit;
    font-size: 0.8rem;
  }
  .save-btn:hover:not(:disabled) {
    border-color: #6e6ef7;
    color: #fff;
  }
  .save-btn:disabled,
  .reset-btn:disabled {
    opacity: 0.45;
    cursor: default;
  }
  .reset-btn {
    padding: 0.4rem 0.85rem;
    background: #16161a;
    border: 1px solid #2a2a35;
    border-radius: 5px;
    color: #aaa;
    cursor: pointer;
    font: inherit;
    font-size: 0.8rem;
  }
  .reset-btn:hover:not(:disabled) {
    color: #e8e8e8;
    border-color: #4a4a55;
  }
  .dirty-note {
    color: #ffd79a;
    font-size: 0.74rem;
  }
  .err {
    color: #ffb4b4;
    font-size: 0.74rem;
    font-family: ui-monospace, SFMono-Regular, monospace;
  }
  .hint {
    color: #888;
    font-size: 0.78rem;
    line-height: 1.6;
    margin-top: 0.6rem;
    max-width: 38rem;
  }
</style>
