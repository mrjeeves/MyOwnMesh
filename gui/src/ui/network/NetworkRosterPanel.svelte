<script lang="ts">
  /** Read-only roster projection plus exact named role operations. Membership
   *  is never edited from the renderer; the daemon applies canonical facts. */
  import { meshClient } from "../../mesh-client.svelte";
  import { governance } from "../../network-governance.svelte";
  import type { AuthorizedPeer, NetworkSummary, Role } from "../../types";
  import { canGrant } from "../../types";
  import RoleChip from "./RoleChip.svelte";
  import NetworkKindBadge from "./NetworkKindBadge.svelte";

  const { network }: { network: NetworkSummary } = $props();
  let roster = $state<AuthorizedPeer[]>([]);
  let error = $state<string | null>(null);
  let busy = $state<string | null>(null);
  const projection = $derived(governance.stateFor(network.config_id));
  const selfPubkey = $derived(meshClient.identity?.pubkey ?? null);
  const myRole = $derived(governance.localRole(network.config_id, selfPubkey));

  function refresh() {
    meshClient.rosterList(network.config_id).then((value) => {
      roster = value;
      error = null;
    }).catch((e) => (error = String(e)));
  }

  $effect(() => {
    void projection;
    refresh();
  });

  function shortId(id: string) {
    return id.length <= 16 ? id : id.slice(0, 8) + "…" + id.slice(-6);
  }

  function canSet(role: Role) {
    return projection.kind === "open" || canGrant(myRole, role);
  }

  async function setRole(peer: AuthorizedPeer, role: Role) {
    if (!selfPubkey || !canSet(role)) return;
    busy = peer.device_id;
    error = null;
    const result = role === "member"
      ? await governance.clearPeerRole(network.config_id, selfPubkey, peer.device_id)
      : await governance.setPeerRole(network.config_id, selfPubkey, peer.device_id, role);
    if (!result.ok) error = result.reason ?? "Role operation refused";
    busy = null;
  }
</script>

<div class="tab">
  <div class="head">
    <h3>Roster</h3>
    <div class="head-meta"><NetworkKindBadge kind={projection.kind} size={13} />
      <span>{roster.length} approved {roster.length === 1 ? "device" : "devices"}</span></div>
  </div>
  <div class="hint">Membership is projected from daemon-owned authenticated roster state. Pending peers appear in Approvals.</div>
  {#if error}<div class="err">⚠ {error}</div>{/if}
  {#if roster.length === 0}
    <div class="empty">No approved devices yet.</div>
  {:else}
    <table class="peers">
      <thead><tr><th>Device</th>{#if projection.kind === "closed"}<th>Role</th>{/if}<th>Approved</th></tr></thead>
      <tbody>
        {#each roster as peer (peer.device_id)}
          {@const isBusy = busy === peer.device_id}
          <tr>
            <td><div>{peer.label || "—"}</div><div class="peer-id mono" title={peer.device_id}>{shortId(peer.device_id)}</div></td>
            {#if projection.kind === "closed"}
              <td><div class="role-cell"><RoleChip role={peer.role} size="sm" />
                <div class="role-menu">
                  {#each ["owner", "controller", "member"] as candidate}
                    {@const role = candidate as Role}
                    <button class:active={peer.role === role} disabled={isBusy || !canSet(role)} title={canSet(role) ? "Set role to " + role : "Your role (" + myRole + ") cannot grant " + role} onclick={() => setRole(peer, role)}>{role}</button>
                  {/each}
                </div>
              </div></td>
            {/if}
            <td class="muted">{new Date(peer.approved_at * 1000).toLocaleString()}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<style>
  .tab { display: flex; flex-direction: column; gap: .6rem; }
  .head { display: flex; align-items: baseline; justify-content: space-between; }
  h3 { margin: 0; color: #e8e8e8; font-size: .92rem; }
  .head-meta { display: flex; gap: .4rem; align-items: center; color: #888; font-size: .74rem; }
  .hint, .muted { color: #8b98a4; font-size: .76rem; }
  .err { color: #ff9d9d; font-size: .8rem; }
  .empty { color: #9da9b3; padding: 1rem; border: 1px dashed #34404a; border-radius: 6px; }
  table { width: 100%; border-collapse: collapse; color: #d7e0e7; font-size: .8rem; }
  th, td { text-align: left; padding: .45rem; border-bottom: 1px solid #202a33; }
  .peer-id { color: #8493a0; font-size: .7rem; }
  .role-cell { display: flex; align-items: center; gap: .5rem; }
  .role-menu { display: flex; gap: .2rem; }
  .role-menu button { background: transparent; color: #aab7c3; border: 1px solid #34424e; border-radius: 3px; padding: .2rem .35rem; font-size: .7rem; }
  .role-menu button.active { color: #fff; border-color: #579bc0; }
  .role-menu button:disabled { opacity: .45; }
</style>
