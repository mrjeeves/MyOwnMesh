<script lang="ts">
  /** Exact daemon governance controls. Kind/topology are config-owned;
   *  roles are changed from the roster panel. This view only exposes the
   *  read-only projection and transactional MFA custody. */
  import { meshClient } from "../../mesh-client.svelte";
  import { governance, type MfaMaterial } from "../../network-governance.svelte";
  import type { NetworkSummary } from "../../types";
  import NetworkKindBadge from "./NetworkKindBadge.svelte";

  const { network }: { network: NetworkSummary } = $props();
  const projection = $derived(governance.stateFor(network.config_id));
  const role = $derived(
    governance.localRole(network.config_id, meshClient.identity?.pubkey ?? null),
  );

  let enrolled = $state(false);
  let material = $state<MfaMaterial | null>(null);
  let busy = $state(false);
  let error = $state<string | null>(null);
  let notice = $state<string | null>(null);
  let disableCode = $state("");

  $effect(() => {
    const id = network.config_id;
    governance.mfaStatus(id).then((value) => {
      if (network.config_id === id) enrolled = value;
    });
  });

  function setMaterial(tx: {
    state: string;
    transaction_id: string;
    secret?: string;
    otpauth_uri?: string;
    recovery_codes?: string[];
  }) {
    if (tx.state !== "prepared") {
      material = null;
      enrolled = tx.state === "committed";
      return;
    }
    if (!tx.secret || !tx.otpauth_uri || !tx.recovery_codes?.length) {
      throw new Error("prepared MFA response omitted recovery material");
    }
    material = {
      secret: tx.secret,
      otpauthUri: tx.otpauth_uri,
      recoveryCodes: tx.recovery_codes,
      transactionId: tx.transaction_id,
    };
    enrolled = false;
  }

  async function prepare() {
    busy = true;
    error = null;
    notice = null;
    const result = await governance.mfaPrepare(network.config_id);
    if (result.ok) material = result.material;
    else error = result.reason;
    busy = false;
  }

  async function query(redeliver: boolean) {
    if (!material) return;
    busy = true;
    error = null;
    try {
      const result = redeliver
        ? await governance.mfaRedeliver(network.config_id, material.transactionId)
        : await governance.mfaQuery(network.config_id, material.transactionId);
      if (result.network !== network.config_id || result.transaction_id !== material.transactionId) {
        throw new Error("MFA response identity did not match this transaction");
      }
      setMaterial(result);
    } catch (e) {
      error = String(e);
    }
    busy = false;
  }

  async function settle(commit: boolean) {
    if (!material) return;
    busy = true;
    error = null;
    notice = null;
    try {
      const result = commit
        ? await governance.mfaCommit(network.config_id, material.transactionId)
        : await governance.mfaAbort(network.config_id, material.transactionId);
      if (result.network !== network.config_id || result.transaction_id !== material.transactionId) {
        throw new Error("MFA response identity did not match this transaction");
      }
      if (commit && result.state !== "committed") {
        throw new Error(`commit returned '${result.state}'; transaction remains recoverable`);
      }
      if (!commit && result.state !== "absent") {
        throw new Error(`abort returned '${result.state}'; transaction was not cleared`);
      }
      setMaterial(result);
      notice = commit ? "Authenticator committed." : "Prepared enrollment aborted.";
    } catch (e) {
      error = String(e);
    }
    busy = false;
  }

  async function disable() {
    busy = true;
    error = null;
    try {
      const result = await governance.mfaDisable(network.config_id, disableCode.trim());
      if (!result.ok) {
        throw new Error("reason" in result ? result.reason : "MFA disable refused");
      }
      enrolled = false;
      disableCode = "";
      notice = "Authenticator disabled.";
    } catch (e) {
      error = String(e);
    }
    busy = false;
  }
</script>

<div class="tab">
  <div class="info-banner" role="status">
    <NetworkKindBadge kind={projection.kind} size={18} />
    <span><strong>{projection.kind}</strong> network · local role <strong>{role}</strong></span>
  </div>
  <div class="card">
    <div class="card-title">Device security · authenticator (MFA)</div>
    <p class="mfa-note">
      MFA enrollment is durable until explicit Commit or Abort. Prepared
      material includes its transaction id and remains redeliverable after a
      lost response or restart; it is never shown after Commit.
    </p>
    {#if enrolled}
      <div class="info-banner" role="status">✓ An authenticator is committed for this device.</div>
      <label class="mfa-field">
        <span>Current code to disable</span>
        <input type="text" bind:value={disableCode} autocomplete="one-time-code" />
      </label>
      <button class="btn" disabled={busy || !disableCode.trim()} onclick={disable}>Disable MFA</button>
    {:else if !material}
      <button class="btn primary" disabled={busy} onclick={prepare}>Prepare authenticator enrollment</button>
    {:else}
      <div class="mfa-enroll-result">
        <p><strong>Save this prepared material before committing.</strong> It can be re-delivered by transaction id.</p>
        <div class="mfa-kv"><span>Transaction</span><code>{material.transactionId}</code></div>
        <div class="mfa-kv"><span>Secret</span><code>{material.secret}</code></div>
        <div class="mfa-kv"><span>otpauth URI</span><code class="wrap">{material.otpauthUri}</code></div>
        <div class="mfa-kv"><span>Recovery codes</span><ul class="mfa-recovery">{#each material.recoveryCodes as code (code)}<li><code>{code}</code></li>{/each}</ul></div>
        <div class="actions">
          <button class="btn" disabled={busy} onclick={() => query(false)}>Query exact transaction</button>
          <button class="btn" disabled={busy} onclick={() => query(true)}>Re-deliver exact material</button>
          <button class="btn primary" disabled={busy} onclick={() => settle(true)}>I saved it — Commit</button>
          <button class="btn ghost" disabled={busy} onclick={() => settle(false)}>Abort</button>
        </div>
      </div>
    {/if}
    {#if notice}<div class="ok" role="status">{notice}</div>{/if}
    {#if error}<div class="mfa-error" role="alert">⚠ {error}</div>{/if}
  </div>
</div>

<style>
  .tab { display: flex; flex-direction: column; gap: .85rem; }
  .card { background: #10151b; border: 1px solid #1c2630; border-radius: 8px; padding: .9rem; }
  .card-title { color: #e8e8e8; font-weight: 600; margin-bottom: .55rem; }
  .info-banner { display: flex; align-items: center; gap: .55rem; background: #131820; border: 1px solid #1c2630; color: #b8c5d0; padding: .55rem .7rem; border-radius: 6px; font-size: .78rem; }
  .mfa-note, .mfa-field, .mfa-kv { color: #aab5bf; font-size: .78rem; line-height: 1.45; }
  .mfa-field { display: flex; flex-direction: column; gap: .3rem; margin: .7rem 0; }
  .mfa-field input { background: #0d1117; color: #eee; border: 1px solid #394552; border-radius: 4px; padding: .4rem; }
  .mfa-enroll-result { display: flex; flex-direction: column; gap: .45rem; }
  .mfa-kv { display: grid; grid-template-columns: 7rem 1fr; gap: .5rem; }
  .mfa-kv code { color: #d7e5ef; overflow-wrap: anywhere; }
  .mfa-recovery { margin: 0; padding-left: 1.2rem; columns: 2; }
  .actions { display: flex; flex-wrap: wrap; gap: .45rem; margin-top: .55rem; }
  .btn { border: 1px solid #3b4b5b; border-radius: 4px; padding: .45rem .65rem; background: #1b2631; color: #dce8ef; cursor: pointer; }
  .btn.primary { background: #245c78; border-color: #4c9bc4; }
  .btn.ghost { background: transparent; }
  .btn:disabled { opacity: .5; cursor: default; }
  .ok { color: #7bd7a4; margin-top: .6rem; font-size: .8rem; }
  .mfa-error { color: #ff9d9d; margin-top: .6rem; font-size: .8rem; }
</style>
