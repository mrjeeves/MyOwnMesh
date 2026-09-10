<script lang="ts">
  /** Read-only authenticated pending-peer projection. Membership changes are
   *  owned by daemon admission; this surface has no roster mutation path. */
  import { meshClient } from "../../mesh-client.svelte";
  import { networkDisplayName } from "../../types";
  import type { NetworkSummary, PeerInfo } from "../../types";

  type PendingRow = { network: NetworkSummary; peer: PeerInfo };
  const ourSuffix = $derived.by(() => {
    const id = meshClient.identity?.device_id ?? "";
    const dash = id.lastIndexOf("-");
    const tail = dash < 0 ? "" : id.slice(dash + 1);
    return tail.length === 5 && /^[0-9A-F]+$/.test(tail) ? tail : "";
  });
  const pending = $derived<PendingRow[]>(
    meshClient.networks.flatMap((network) =>
      (meshClient.peersByNetwork[network.config_id] ?? [])
        .filter((peer) => peer.status === "pending_approval")
        .map((peer) => ({ network, peer })),
    ),
  );

  function shortId(id: string) {
    return id.length <= 14 ? id : id.slice(0, 10) + "…" + id.slice(-4);
  }
</script>

<div class="content">
  <div class="head">
    <h3>Pending authenticated peers</h3>
    {#if pending.length > 0}<span class="count">{pending.length} waiting</span>{/if}
  </div>
  <div class="hint">These are authenticated session observations awaiting daemon policy admission. Membership is never changed by a browser-side roster operation.</div>
  {#if pending.length === 0}
    <div class="empty-state"><p class="empty-title">No pending peers.</p><p>When another device authenticates, its exact identity and session observations appear here.</p></div>
  {:else}
    <div class="list">
      {#each pending as row (row.peer.device_id + ":" + row.network.config_id)}
        <div class="row">
          <div class="row-head">
            <div>
              <span class="peer-label">{row.peer.label || "Unnamed device"}</span>
              <span class="net-chip">on <strong>{networkDisplayName(row.network)}</strong></span>
            </div>
            <code class="pubkey" title={row.peer.device_id}>{shortId(row.peer.device_id)}</code>
          </div>
          <div class="confirm-grid">
            <div class="confirm-col"><div class="confirm-side-label">this device</div><div class="confirm-pair">{#if ourSuffix}<div class="confirm-tile suffix-tile"><span class="confirm-label">suffix</span><span class="confirm-value">{ourSuffix}</span></div>{/if}</div></div>
            <div class="confirm-divider" aria-hidden="true">↔</div>
            <div class="confirm-col"><div class="confirm-side-label">peer</div><div class="confirm-pair">{#if row.peer.device_suffix}<div class="confirm-tile suffix-tile"><span class="confirm-label">suffix</span><span class="confirm-value">{row.peer.device_suffix}</span></div>{/if}{#if row.peer.verification_code_received}<div class="confirm-tile code-tile"><span class="confirm-label">code</span><span class="confirm-value">{row.peer.verification_code_received}</span></div>{/if}</div></div>
          </div>
          <div class="status">Awaiting daemon admission and exact named role policy.</div>
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .content { flex: 1; overflow-y: auto; padding: 1rem 1.25rem; max-width: 50rem; }
  .head { display: flex; align-items: baseline; justify-content: space-between; }
  h3 { margin: 0; color: #e8e8e8; font-size: .92rem; }
  .count, .hint, .status { color: #8b98a4; font-size: .76rem; }
  .hint { margin: .7rem 0; line-height: 1.4; }
  .empty-state, .row { border: 1px solid #26313b; border-radius: 7px; padding: .8rem; background: #10151b; }
  .empty-title { color: #e8e8e8; font-weight: 600; }
  .list { display: flex; flex-direction: column; gap: .6rem; }
  .row-head { display: flex; justify-content: space-between; gap: .5rem; }
  .peer-label { color: #e6edf3; font-weight: 600; }
  .net-chip { margin-left: .5rem; color: #91a1ad; font-size: .74rem; }
  .pubkey { color: #91a1ad; font-size: .7rem; }
  .confirm-grid { display: grid; grid-template-columns: 1fr auto 1fr; gap: .5rem; align-items: center; margin: .8rem 0; }
  .confirm-side-label, .confirm-label { color: #8493a0; font-size: .68rem; text-transform: uppercase; }
  .confirm-pair { display: flex; flex-wrap: wrap; gap: .35rem; margin-top: .25rem; }
  .confirm-tile { border: 1px solid #354653; border-radius: 4px; padding: .35rem .45rem; display: flex; flex-direction: column; }
  .confirm-value { color: #dce8ef; font-family: monospace; font-size: .8rem; }
  .confirm-divider { color: #6398b5; }
</style>
