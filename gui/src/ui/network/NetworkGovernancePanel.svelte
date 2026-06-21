<script lang="ts">
  /** Governance panel (Settings → Networks → Governance) — the
   *  open/closed kind toggle and the propose/sign/deny/split flow from
   *  `docs/NETWORK-TYPES.md`.
   *
   *  Backed by the daemon: every action here round-trips through the
   *  `network-governance.svelte.ts` store, which signs and broadcasts a
   *  `network_state_*` frame via the control socket. The engine verifies
   *  each signature and only ratifies a transition once its signer set
   *  satisfies the quorum table — the wire, not this UI, is the security
   *  boundary. The role gates below are convenience, keeping a user from
   *  issuing a request the engine would just reject. */

  import { meshClient } from "../../mesh-client.svelte";
  import {
    STATE_PROPOSAL_TIMEOUT_S,
    governance,
  } from "../../network-governance.svelte";
  import type { NetworkSummary, PendingProposal } from "../../types";
  import NetworkKindBadge from "./NetworkKindBadge.svelte";

  const {
    network,
  }: {
    network: NetworkSummary;
  } = $props();

  const govView = $derived(governance.stateFor(network.config_id));
  const selfPubkey = $derived(meshClient.identity?.pubkey ?? null);
  const myRole = $derived(governance.localRole(network.config_id, selfPubkey));
  const peers = $derived(meshClient.peersByNetwork[network.config_id] ?? []);
  const onlineCount = $derived(
    peers.filter((p) => p.status === "active" || p.status === "shelved").length,
  );

  let actionError = $state<string | null>(null);
  let busy = $state(false);

  // ---- per-device custody MFA (TOTP) ----
  // When this device has enrolled a custody lock for the network, the daemon
  // refuses to author/sign a governance change without a fresh code. We pass
  // whatever the user typed in `mfaCode`; an empty value is sent as undefined
  // (no factor), and any daemon refusal surfaces in `actionError`.
  let mfaEnrolled = $state(false);
  let mfaCode = $state("");
  let mfaBusy = $state(false);
  let mfaError = $state<string | null>(null);
  let mfaEnrollResult = $state<{
    secret: string;
    otpauthUri: string;
    recoveryCodes: string[];
  } | null>(null);
  let mfaDisableCode = $state("");

  $effect(() => {
    // Re-load enrollment status whenever the selected network changes.
    const id = network.config_id;
    governance.mfaStatus(id).then((on) => {
      if (network.config_id === id) mfaEnrolled = on;
    });
  });

  function codeArg(): string | undefined {
    const c = mfaCode.trim();
    return c.length ? c : undefined;
  }

  async function propose(to: "open" | "closed") {
    if (!selfPubkey) {
      actionError = "Local identity not loaded yet — try again in a moment.";
      return;
    }
    busy = true;
    actionError = null;
    const r = await governance.proposeKindChange(
      network.config_id,
      selfPubkey,
      to,
      codeArg(),
    );
    if (!r.ok) actionError = r.reason ?? "Couldn't float proposal.";
    else mfaCode = "";
    busy = false;
  }

  async function sign(p: PendingProposal) {
    if (!selfPubkey) return;
    busy = true;
    actionError = null;
    const r = await governance.signProposal(
      network.config_id,
      selfPubkey,
      p.id,
      codeArg(),
    );
    if (!r.ok) actionError = r.reason ?? "Couldn't sign.";
    else mfaCode = "";
    busy = false;
  }

  async function enrollMfa() {
    mfaBusy = true;
    mfaError = null;
    const r = await governance.mfaEnroll(network.config_id);
    if (r.ok) {
      mfaEnrollResult = {
        secret: r.secret,
        otpauthUri: r.otpauthUri,
        recoveryCodes: r.recoveryCodes,
      };
      mfaEnrolled = true;
    } else {
      mfaError = r.reason ?? "Couldn't enroll.";
    }
    mfaBusy = false;
  }

  async function disableMfa() {
    mfaBusy = true;
    mfaError = null;
    const r = await governance.mfaDisable(
      network.config_id,
      mfaDisableCode.trim(),
    );
    if (r.ok) {
      mfaEnrolled = false;
      mfaEnrollResult = null;
      mfaDisableCode = "";
    } else {
      mfaError = r.reason ?? "Couldn't disable (wrong code?).";
    }
    mfaBusy = false;
  }

  async function deny(p: PendingProposal) {
    if (!selfPubkey) return;
    busy = true;
    actionError = null;
    const r = await governance.denyProposal(network.config_id, selfPubkey, p.id);
    if (!r.ok) actionError = r.reason ?? "Couldn't deny.";
    busy = false;
  }

  async function withdraw(p: PendingProposal) {
    if (!selfPubkey) return;
    busy = true;
    actionError = null;
    const r = await governance.withdrawProposal(network.config_id, selfPubkey, p.id);
    if (!r.ok) actionError = r.reason ?? "Couldn't withdraw.";
    busy = false;
  }

  async function split(p: PendingProposal) {
    if (!selfPubkey) return;
    busy = true;
    actionError = null;
    const r = await governance.spawnSplit(
      network.config_id,
      selfPubkey,
      p.id,
      network.network_id,
    );
    if (!r.ok) actionError = r.reason ?? "Couldn't spawn split.";
    busy = false;
  }

  function fmtAge(ms: number): string {
    const diff = Math.floor((Date.now() - ms) / 1000);
    if (diff < 60) return `${diff}s`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h`;
    return `${Math.floor(diff / 86400)}d`;
  }

  function splitEligible(p: PendingProposal): boolean {
    if (p.variant.kind !== "kind_change" || p.variant.to !== "closed") return false;
    if (p.split_spawned) return false;
    const ageS = (Date.now() - p.created_at) / 1000;
    return ageS >= STATE_PROPOSAL_TIMEOUT_S;
  }

  function describe(p: PendingProposal): string {
    const v = p.variant;
    switch (v.kind) {
      case "kind_change":
        return `Change network kind → ${v.to}`;
      case "role_grant":
        return `Grant ${v.to} to ${v.target.slice(0, 10)}…`;
      case "role_revoke":
        return `Revoke role from ${v.target.slice(0, 10)}…`;
      case "split":
        return `Split → ${v.new_network_id.slice(0, 10)}…`;
    }
  }
</script>

<div class="tab">
  <div class="info-banner" role="status">
    Governance is enforced at the engine: every transition rides as
    a signed <code>network_state</code> frame, peers verify each
    signature, and the daemon drops frames whose signer set doesn't
    satisfy the quorum table. See
    <code>docs/NETWORK-TYPES.md</code> for the spec.
  </div>

  {#if actionError}
    <div class="err">⚠ {actionError}</div>
  {/if}

  <div class="card">
    <div class="head">
      <div class="title">
        <NetworkKindBadge kind={govView.kind} size={18} />
        <span>Network is <strong>{govView.kind}</strong></span>
      </div>
    </div>
    <div class="explain">
      {#if govView.kind === "open"}
        Any current member can add to the roster. Roles are
        cosmetic — no one's authority is enforced. Anyone holding
        the network id can knock; approvals happen one-to-one in
        the Approvals tab.
      {:else}
        Only controllers and owners can add to the roster. Members
        can <em>propose</em> additions; an owner or controller has
        to co-sign before the addition lands. Network-kind
        transitions need unanimous member consent.
      {/if}
    </div>

    <div class="actions">
      {#if govView.kind === "open"}
        <button
          class="btn primary"
          disabled={busy || govView.pending.some(
            (p) => p.variant.kind === "kind_change" && p.variant.to === "closed",
          )}
          onclick={() => propose("closed")}
          title="Float a proposal to close this network. Every current member must sign before it lands; if some stall, you can spawn a split with the signers you have."
        >
          Propose close (→ closed)
        </button>
      {:else}
        <button
          class="btn primary"
          disabled={busy || govView.pending.some(
            (p) => p.variant.kind === "kind_change" && p.variant.to === "open",
          ) || myRole !== "owner"}
          onclick={() => propose("open")}
          title={myRole === "owner"
            ? "Float a proposal to open this network. Every current owner must sign."
            : "Only owners can propose opening a closed network."}
        >
          Propose open (→ open)
        </button>
      {/if}
    </div>
  </div>

  <div class="card">
    <div class="card-title">Device security · authenticator (MFA)</div>
    <p class="mfa-note">
      A per-device second factor. When enrolled, this device won't author or
      co-sign a governance change (owner grant/revoke, kind change) without a
      fresh code from your authenticator app. It guards <em>this device's</em>
      signing key; it doesn't replace the network's owner-quorum.
    </p>

    {#if mfaEnrolled}
      <div class="info-banner" role="status">
        ✓ An authenticator is enrolled on this device for this network.
      </div>

      <label class="mfa-field">
        <span>Authenticator code — used when you propose / sign below</span>
        <input
          type="text"
          inputmode="numeric"
          autocomplete="one-time-code"
          placeholder="6-digit code or a recovery code"
          bind:value={mfaCode}
        />
      </label>

      <details class="mfa-disable">
        <summary>Remove this device's authenticator</summary>
        <label class="mfa-field">
          <span>Enter a current code to confirm</span>
          <input
            type="text"
            bind:value={mfaDisableCode}
            placeholder="6-digit code or a recovery code"
          />
        </label>
        <button
          class="btn"
          disabled={mfaBusy || !mfaDisableCode.trim()}
          onclick={disableMfa}
        >
          Disable MFA
        </button>
      </details>
    {:else}
      <button class="btn primary" disabled={mfaBusy} onclick={enrollMfa}>
        Enroll an authenticator
      </button>
    {/if}

    {#if mfaEnrollResult}
      <div class="mfa-enroll-result">
        <p>
          <strong>Add this to your authenticator app now, and save the
          recovery codes</strong> — they won't be shown again.
        </p>
        <div class="mfa-kv"><span>Secret</span><code>{mfaEnrollResult.secret}</code></div>
        <div class="mfa-kv">
          <span>otpauth URI</span><code class="wrap">{mfaEnrollResult.otpauthUri}</code>
        </div>
        <div class="mfa-kv">
          <span>Recovery codes</span>
          <ul class="mfa-recovery">
            {#each mfaEnrollResult.recoveryCodes as rc (rc)}
              <li><code>{rc}</code></li>
            {/each}
          </ul>
        </div>
        <button class="btn" onclick={() => (mfaEnrollResult = null)}>
          I've saved these
        </button>
      </div>
    {/if}

    {#if mfaError}
      <div class="mfa-error" role="alert">{mfaError}</div>
    {/if}
  </div>

  {#if govView.pending.length > 0}
    <div class="card">
      <div class="card-title">Pending proposals</div>
      <div class="proposals">
        {#each govView.pending as p (p.id)}
          {@const isProposer = p.proposer === selfPubkey}
          {@const alreadySigned = selfPubkey ? p.signers.includes(selfPubkey) : false}
          {@const alreadyDenied = selfPubkey ? p.deniers.includes(selfPubkey) : false}
          {@const dead = p.deniers.length > 0}
          <div class="proposal" data-dead={dead}>
            <div class="prop-head">
              <div class="prop-summary">
                <span class="prop-title">{describe(p)}</span>
                {#if dead}
                  <span class="state-pill denied">denied</span>
                {:else if alreadySigned}
                  <span class="state-pill signed">you signed</span>
                {:else}
                  <span class="state-pill pending">awaiting your sign</span>
                {/if}
                {#if splitEligible(p)}
                  <span class="state-pill stuck">split eligible</span>
                {/if}
              </div>
              <div class="prop-meta">
                {fmtAge(p.created_at)} ago · by
                <code class="mono">
                  {isProposer ? "you" : `${p.proposer.slice(0, 8)}…`}
                </code>
              </div>
            </div>

            <div class="prop-sig">
              <div>
                <span class="sig-label">Signers</span>
                <span>{p.signers.length} ({p.signers.map((s) => (s === selfPubkey ? "you" : s.slice(0, 6) + "…")).join(", ")})</span>
              </div>
              {#if p.deniers.length > 0}
                <div class="deniers">
                  <span class="sig-label">Deniers</span>
                  <span>{p.deniers.length} ({p.deniers.map((s) => (s === selfPubkey ? "you" : s.slice(0, 6) + "…")).join(", ")})</span>
                </div>
              {/if}
            </div>

            <div class="prop-actions">
              {#if !dead}
                {#if !alreadySigned}
                  <button
                    class="btn primary sm"
                    disabled={busy}
                    onclick={() => sign(p)}
                  >
                    Sign
                  </button>
                {/if}
                {#if !alreadyDenied}
                  <button
                    class="btn ghost sm"
                    disabled={busy}
                    onclick={() => deny(p)}
                  >
                    Deny
                  </button>
                {/if}
              {/if}
              {#if isProposer}
                <button
                  class="btn ghost sm"
                  disabled={busy}
                  onclick={() => withdraw(p)}
                >
                  Withdraw
                </button>
                {#if splitEligible(p)}
                  <button
                    class="btn warn sm"
                    disabled={busy}
                    onclick={() => split(p)}
                    title="Spawn a derived closed network from the signers you have. The original network is unaffected — every non-signer stays where they are, with the rules they had."
                  >
                    Spawn split
                  </button>
                {/if}
              {/if}
            </div>

            <div class="prop-explain">
              {#if p.variant.kind === "kind_change" && p.variant.to === "closed"}
                Every current member must sign before the close
                lands. If some are silent past
                <code>{Math.round(STATE_PROPOSAL_TIMEOUT_S / 60)} min</code>,
                the would-be owner (proposer) can spawn a derived
                closed network with the signers they have —
                non-signers stay in the original open network.
              {:else if p.variant.kind === "kind_change" && p.variant.to === "open"}
                Every current owner must sign. A single deny
                invalidates the proposal.
              {:else if p.variant.kind === "role_grant"}
                A role grant needs co-signature from an authority
                above (or equal to, for `member`) the granted role.
              {:else if p.variant.kind === "split"}
                Split spawned. The new network's id and member list
                are signed; signers can join it from their network
                list.
              {/if}
            </div>
          </div>
        {/each}
      </div>
    </div>
  {/if}

  <div class="card">
    <div class="card-title">Topology of authority</div>
    <ul class="auth">
      <li>
        <strong>Open</strong> — any member adds to the roster, no
        role gates. Today's default. The engine treats every entry
        the same.
      </li>
      <li>
        <strong>Closed · member</strong> — no roster authority. Can
        propose additions; a controller or owner has to co-sign.
      </li>
      <li>
        <strong>Closed · controller</strong> — can add members. Can't
        grant <code>controller</code> or <code>owner</code>.
      </li>
      <li>
        <strong>Closed · owner</strong> — can grant any role, can
        approve network-kind transitions, can revoke any other
        owner. Every owner-grant needs unanimous owner consent.
      </li>
    </ul>
    <div class="muted small">
      Closed-network state is per-network. Two networks with the same
      members can have different kinds and different role
      assignments; they don't leak into each other.
    </div>
  </div>

  <div class="card">
    <div class="card-title">Mesh quorum reference</div>
    <dl class="quorum">
      <dt>open → closed</dt>
      <dd>unanimous of current members (proposer-initiated split fallback after {Math.round(STATE_PROPOSAL_TIMEOUT_S / 60)} min)</dd>
      <dt>closed → open</dt>
      <dd>unanimous of current owners</dd>
      <dt>grant owner</dt>
      <dd>unanimous of current owners</dd>
      <dt>grant controller</dt>
      <dd>≥ 1 owner signature</dd>
      <dt>add member</dt>
      <dd>≥ 1 controller or owner signature</dd>
    </dl>
    <div class="muted small">
      The engine enforces the table above: a transition only ratifies
      once its signer set satisfies the quorum, and a single deny kills a
      proposal.
      <span>Currently <strong>{onlineCount}</strong> peer{onlineCount === 1 ? "" : "s"} online.</span>
    </div>
  </div>
</div>

<style>
  .tab {
    display: flex;
    flex-direction: column;
    gap: 0.85rem;
  }
  .info-banner {
    background: #131820;
    border: 1px solid #1c2630;
    color: #b8c5d0;
    padding: 0.55rem 0.7rem;
    border-radius: 6px;
    font-size: 0.78rem;
    line-height: 1.45;
  }
  .info-banner code {
    background: #1a1a22;
    padding: 0.02rem 0.3rem;
    border-radius: 3px;
    font-size: 0.72rem;
  }
  .err {
    background: #3a1717;
    color: #ffb4b4;
    border: 1px solid #5a2424;
    border-radius: 5px;
    padding: 0.45rem 0.6rem;
    font-size: 0.78rem;
  }
  .card {
    background: #131318;
    border: 1px solid #1e1e25;
    border-radius: 8px;
    padding: 0.85rem 1rem;
  }
  .card-title {
    font-weight: 600;
    font-size: 0.85rem;
    margin-bottom: 0.6rem;
    color: #ccc;
  }
  .head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.5rem;
  }
  .title {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.95rem;
    color: #e8e8e8;
  }
  .title strong {
    text-transform: capitalize;
  }
  .explain {
    color: #b8c5d0;
    font-size: 0.82rem;
    line-height: 1.5;
    margin-bottom: 0.8rem;
  }
  .explain em {
    color: #d8e0ea;
  }
  .actions {
    display: flex;
    gap: 0.5rem;
  }
  .btn {
    padding: 0.45rem 0.85rem;
    border-radius: 5px;
    border: 1px solid #2a2a35;
    background: #1a1a22;
    color: #ccc;
    cursor: pointer;
    font: inherit;
    font-size: 0.82rem;
  }
  .btn.sm {
    padding: 0.3rem 0.6rem;
    font-size: 0.76rem;
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
  .btn.ghost {
    background: none;
  }
  .btn.warn {
    background: #2a200c;
    border-color: #4a3a14;
    color: #fbbf24;
  }
  .btn.warn:hover:not(:disabled) {
    background: #3a2a14;
  }
  .btn:disabled {
    opacity: 0.45;
    cursor: default;
  }
  .proposals {
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }
  .proposal {
    background: #0d0d12;
    border: 1px solid #1e1e25;
    border-radius: 6px;
    padding: 0.6rem 0.75rem;
    display: flex;
    flex-direction: column;
    gap: 0.45rem;
  }
  .proposal[data-dead="true"] {
    opacity: 0.6;
  }
  .prop-head {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }
  .prop-summary {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
  }
  .prop-title {
    font-weight: 500;
    color: #e8e8e8;
    font-size: 0.85rem;
  }
  .prop-meta {
    color: #888;
    font-size: 0.72rem;
  }
  .state-pill {
    font-size: 0.62rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    padding: 0.1rem 0.45rem;
    border-radius: 999px;
    background: #161618;
    border: 1px solid #222226;
    color: #888;
  }
  .state-pill.signed {
    color: #b9f5cc;
    background: #112a1c;
    border-color: #1c4a30;
  }
  .state-pill.pending {
    color: #fbbf24;
    background: #2a200c;
    border-color: #4a3a14;
  }
  .state-pill.denied {
    color: #fca5a5;
    background: #2a1414;
    border-color: #4a2222;
  }
  .state-pill.stuck {
    color: #fb923c;
    background: #2a1a0c;
    border-color: #4a3214;
  }
  .prop-sig {
    display: flex;
    gap: 1rem;
    font-size: 0.76rem;
    color: #ccc;
    flex-wrap: wrap;
  }
  .deniers {
    color: #fca5a5;
  }
  .sig-label {
    color: #888;
    margin-right: 0.3rem;
    font-size: 0.7rem;
  }
  .prop-actions {
    display: flex;
    gap: 0.4rem;
    flex-wrap: wrap;
  }
  .prop-explain {
    color: #94a3b8;
    font-size: 0.74rem;
    line-height: 1.45;
    padding-top: 0.25rem;
    border-top: 1px solid #1a1a20;
  }
  .prop-explain code {
    background: #1a1a22;
    padding: 0.02rem 0.3rem;
    border-radius: 3px;
    font-size: 0.7rem;
  }
  .auth {
    list-style: none;
    padding: 0;
    margin: 0 0 0.5rem;
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    font-size: 0.8rem;
    color: #ccc;
  }
  .auth strong {
    color: #e8e8e8;
  }
  .auth code {
    background: #1a1a22;
    padding: 0.02rem 0.3rem;
    border-radius: 3px;
    font-size: 0.74rem;
  }
  .quorum {
    display: grid;
    grid-template-columns: 12rem 1fr;
    gap: 0.35rem 0.85rem;
    font-size: 0.8rem;
    margin-bottom: 0.5rem;
  }
  .quorum dt {
    color: #888;
    font-family: ui-monospace, SFMono-Regular, monospace;
    font-size: 0.74rem;
  }
  .quorum dd {
    color: #ccc;
  }
  .muted {
    color: #888;
    font-size: 0.74rem;
    line-height: 1.4;
  }
  .small {
    font-size: 0.72rem;
  }
  .mono {
    font-family: ui-monospace, SFMono-Regular, monospace;
  }

  /* ---- custody MFA section ---- */
  .mfa-note {
    margin: 0 0 0.6rem;
    font-size: 0.8rem;
    opacity: 0.8;
  }
  .mfa-field {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    margin: 0.6rem 0;
    font-size: 0.78rem;
  }
  .mfa-field input {
    padding: 0.4rem 0.5rem;
    border-radius: 6px;
    border: 1px solid rgba(127, 127, 127, 0.4);
    font-family: ui-monospace, SFMono-Regular, monospace;
  }
  .mfa-disable {
    margin-top: 0.6rem;
    font-size: 0.78rem;
  }
  .mfa-disable summary {
    cursor: pointer;
    opacity: 0.8;
  }
  .mfa-enroll-result {
    margin-top: 0.7rem;
    padding: 0.7rem;
    border: 1px solid rgba(127, 127, 127, 0.35);
    border-radius: 8px;
  }
  .mfa-kv {
    display: flex;
    gap: 0.5rem;
    align-items: baseline;
    margin: 0.35rem 0;
    font-size: 0.78rem;
  }
  .mfa-kv > span {
    min-width: 6.5rem;
    opacity: 0.7;
  }
  .mfa-kv code.wrap {
    word-break: break-all;
  }
  .mfa-recovery {
    margin: 0;
    padding-left: 1rem;
    columns: 2;
  }
  .mfa-error {
    margin-top: 0.6rem;
    padding: 0.4rem 0.6rem;
    border-radius: 6px;
    background: rgba(220, 70, 70, 0.12);
    color: #c0392b;
    font-size: 0.8rem;
  }
</style>
