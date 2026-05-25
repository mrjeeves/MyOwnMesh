<script lang="ts">
  /** Roster tab in the per-network overlay. Approved peers + their
   *  role in the network's governance model.
   *
   *  Role column is always shown so the affordance is discoverable
   *  even on `open` networks (where the role tag is cosmetic until
   *  the network goes `closed`). On `closed` networks the role
   *  selector enforces grant-authority — members can't promote
   *  anyone, controllers can grant up to `controller`, owners can
   *  grant anything. */

  import { save as saveDialog } from "@tauri-apps/plugin-dialog";
  import { meshClient } from "../../mesh-client.svelte";
  import { governance } from "../../network-governance.svelte";
  import type {
    AuthorizedPeer,
    NetworkConfigInput,
    NetworkSummary,
    Role,
  } from "../../types";
  import { canGrant, ROLE_RANK } from "../../types";
  import {
    exportNetworkSettings,
  } from "../../network-settings";
  import {
    buildApprovalExport,
    buildIdentityExport,
    isIdentityExport,
    suggestedFilename,
    tryParsePortable,
    writePortableFile,
    type IdentityExport,
  } from "../../identity-portable";
  import RoleChip from "./RoleChip.svelte";
  import NetworkKindBadge from "./NetworkKindBadge.svelte";

  const {
    network,
  }: {
    network: NetworkSummary;
  } = $props();

  let roster = $state<AuthorizedPeer[]>([]);
  let rosterError = $state<string | null>(null);
  let actionError = $state<string | null>(null);
  let busy = $state<string | null>(null);

  const govView = $derived(governance.stateFor(network.config_id));
  const selfPubkey = $derived(meshClient.identity?.pubkey ?? null);
  const myRole = $derived(governance.localRole(network.config_id, selfPubkey));

  async function refresh() {
    try {
      roster = await meshClient.rosterList(network.config_id);
      rosterError = null;
    } catch (e) {
      rosterError = String(e);
    }
  }

  $effect(() => {
    void refresh();
  });

  function shortId(id: string): string {
    if (id.length <= 16) return id;
    return id.slice(0, 8) + "…" + id.slice(-6);
  }

  function fmtDate(epoch: number): string {
    return new Date(epoch * 1000).toLocaleString();
  }

  function roleOf(deviceId: string): Role {
    // Roster entries from the daemon don't (yet) carry the role
    // field — the engine isn't aware of governance. Read from the
    // GUI-local governance store; default to `member`.
    return governance.roleOf(network.config_id, devicePubkey(deviceId));
  }

  /** Strip a roster entry's display-suffix to get the bare pubkey
   *  the governance store keys on. Roster entries are stored as
   *  raw pubkeys today, but in case a display-id ever leaks
   *  through (e.g. user pasted one into a CLI), tolerate it. */
  function devicePubkey(deviceId: string): string {
    const dash = deviceId.lastIndexOf("-");
    if (dash === -1) return deviceId;
    const tail = deviceId.slice(dash + 1);
    if (tail.length === 5 && /^[0-9A-F]+$/.test(tail)) {
      return deviceId.slice(0, dash);
    }
    return deviceId;
  }

  async function setRole(peer: AuthorizedPeer, role: Role) {
    if (!selfPubkey) {
      actionError = "Local identity not loaded yet — try again in a moment.";
      return;
    }
    busy = peer.device_id;
    actionError = null;
    const peerPub = devicePubkey(peer.device_id);
    const result = role === "member"
      ? await governance.clearPeerRole(network.config_id, selfPubkey, peerPub)
      : await governance.setPeerRole(network.config_id, selfPubkey, peerPub, role);
    if (!result.ok) {
      actionError = result.reason ?? "Couldn't change role.";
    }
    busy = null;
  }

  async function removePeer(peer: AuthorizedPeer) {
    busy = peer.device_id;
    actionError = null;
    try {
      await meshClient.rosterRemove(network.config_id, peer.device_id);
      await refresh();
    } catch (e) {
      actionError = String(e);
    } finally {
      busy = null;
    }
  }

  // ---- identity import (pre-authorise a peer) -------------------------

  let importBusy = $state(false);
  let importInfo = $state<string | null>(null);
  let fileInput = $state<HTMLInputElement | null>(null);

  function clickImport() {
    fileInput?.click();
  }

  function onFilePicked(e: Event) {
    const input = e.currentTarget as HTMLInputElement;
    const file = input.files && input.files.length > 0 ? input.files[0] : null;
    input.value = "";
    if (!file) return;
    file
      .text()
      .then((text) => importIdentity(text))
      .catch((e) => {
        actionError = `Couldn't read file: ${String(e)}`;
      });
  }

  async function importIdentity(text: string) {
    actionError = null;
    importInfo = null;
    const parsed = tryParsePortable(text);
    if (!parsed) {
      actionError =
        'File doesn\'t look like a MyOwnMesh identity export. Expected JSON with "kind": "myownmesh.identity".';
      return;
    }
    // Both `myownmesh.identity` and `myownmesh.approval` carry a
    // pubkey we can roster-approve. Identity is the common path;
    // approval bundles work too (we lift the `approver` block).
    const id: IdentityExport =
      parsed.kind === "identity"
        ? parsed.value
        : parsed.value.approver;
    if (!isIdentityExport(id) && parsed.kind !== "approval") {
      actionError = "Imported file's identity block is malformed.";
      return;
    }

    importBusy = true;
    try {
      // `roster_approve` accepts any device_id — when no live
      // session exists yet, the approval is persisted to the
      // on-disk roster file and the daemon auto-approves on the
      // peer's first handshake. Exactly the pre-auth flow we want.
      await meshClient.rosterApprove(
        network.config_id,
        id.pubkey,
        id.label ?? "",
      );
      importInfo = `Pre-approved ${id.label || id.pubkey.slice(0, 12)}… on this network. ` +
        `They'll auto-approve on first connection.`;
      await refresh();
    } catch (e) {
      actionError = `Pre-approval failed: ${String(e)}`;
    } finally {
      importBusy = false;
    }
  }

  // ---- approval export (issue out-of-band approval for a roster entry) ----

  async function exportApproval(peer: AuthorizedPeer) {
    if (!meshClient.identity) {
      actionError = "Local identity not loaded yet.";
      return;
    }
    busy = peer.device_id;
    actionError = null;
    try {
      const cfg = await meshClient.configShow();
      const net = cfg.networks.find(
        (n: NetworkConfigInput) =>
          n.id === network.config_id || n.network_id === network.network_id,
      );
      if (!net) {
        actionError =
          "Network has no saved config to bundle into the approval.";
        return;
      }
      const envelope = buildApprovalExport({
        network: exportNetworkSettings(net),
        approver: buildIdentityExport({
          pubkey: meshClient.identity.pubkey,
          deviceId: meshClient.identity.device_id,
          label: meshClient.identity.label,
        }),
        approvedPubkey: devicePubkey(peer.device_id),
        approvedLabel: peer.label,
      });
      const path = await saveDialog({
        defaultPath: suggestedFilename(envelope),
        filters: [{ name: "MyOwnMesh approval", extensions: ["json"] }],
      });
      if (!path) return;
      await writePortableFile(path, envelope);
    } catch (e) {
      actionError = `Approval export failed: ${String(e)}`;
    } finally {
      busy = null;
    }
  }

  function whyDisabled(target: Role): string | null {
    if (govView.kind === "open") return null;
    if (!canGrant(myRole, target)) {
      if (myRole === "member") {
        return "Members can't grant roles in a closed network.";
      }
      if (ROLE_RANK[myRole] < ROLE_RANK[target]) {
        return `Your role (${myRole}) can't grant ${target}.`;
      }
    }
    return null;
  }
</script>

<div class="tab">
  <div class="head">
    <h3>Roster</h3>
    <div class="head-meta">
      <NetworkKindBadge kind={govView.kind} size={13} />
      <span>{roster.length} approved {roster.length === 1 ? "device" : "devices"}</span>
    </div>
  </div>

  {#if rosterError}
    <div class="err">⚠ {rosterError}</div>
  {/if}
  {#if actionError}
    <div class="err">⚠ {actionError}</div>
  {/if}
  {#if importInfo}
    <div class="ok">{importInfo}</div>
  {/if}

  <div class="import-row">
    <button
      class="row-btn"
      disabled={importBusy}
      onclick={clickImport}
      title="Import a .identity.json file from another device to pre-authorise them on this network. The next time they connect, they auto-approve without the verification-code dance."
    >
      {importBusy ? "Importing…" : "+ Import identity…"}
    </button>
    <span class="hint">
      Pre-authorise a peer before they connect.
    </span>
    <input
      bind:this={fileInput}
      type="file"
      accept=".json,application/json"
      onchange={onFilePicked}
      style="display: none"
    />
  </div>

  {#if roster.length === 0}
    <div class="empty">
      No approved devices yet. Approvals land here once you accept
      a pending peer in the <strong>Approvals</strong> tab — or
      import an identity file (above) to pre-authorise a peer that
      hasn't connected yet.
    </div>
  {:else}
    <table class="peers">
      <thead>
        <tr>
          <th>Device</th>
          {#if govView.kind === "closed"}
            <th>Role</th>
          {/if}
          <th>Approved</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each roster as r (r.device_id)}
          {@const role = roleOf(r.device_id)}
          {@const isBusy = busy === r.device_id}
          <tr>
            <td>
              <div class="peer-label">{r.label || "—"}</div>
              <div class="peer-id mono" title={r.device_id}>
                {shortId(r.device_id)}
              </div>
            </td>
            {#if govView.kind === "closed"}
              <td>
                <div class="role-cell">
                  <RoleChip {role} size="sm" />
                  <div class="role-menu">
                    {#each ["owner", "controller", "member"] as r2}
                      {@const disabled = !!whyDisabled(r2 as Role)}
                      <button
                        class="role-opt"
                        class:active={role === r2}
                        {disabled}
                        title={whyDisabled(r2 as Role) ?? `Set role to ${r2}`}
                        onclick={() => setRole(r, r2 as Role)}
                      >
                        {r2}
                      </button>
                    {/each}
                  </div>
                </div>
              </td>
            {/if}
            <td class="muted">{fmtDate(r.approved_at)}</td>
            <td>
              <div class="row-actions">
                <button
                  class="row-btn"
                  disabled={isBusy}
                  onclick={() => exportApproval(r)}
                  title="Issue an out-of-band approval bundle for this peer. Writes a .approval.json containing this network's settings + your identity + the peer's pubkey. They import it elsewhere to join the same network with you already in their roster."
                >
                  Approval…
                </button>
                <button
                  class="row-btn danger"
                  disabled={isBusy}
                  onclick={() => removePeer(r)}
                >
                  Remove
                </button>
              </div>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<style>
  .tab {
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }
  .head {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 0.6rem;
    margin-bottom: 0.2rem;
  }
  h3 {
    margin: 0;
    font-size: 0.92rem;
    font-weight: 600;
    color: #e8e8e8;
  }
  .head-meta {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.74rem;
    color: #888;
  }
  .muted {
    color: #888;
  }
  .err {
    background: #3a1717;
    color: #ffb4b4;
    border: 1px solid #5a2424;
    border-radius: 5px;
    padding: 0.45rem 0.6rem;
    font-size: 0.78rem;
  }
  .ok {
    background: #112a1c;
    color: #b9f5cc;
    border: 1px solid #1c4a30;
    border-radius: 5px;
    padding: 0.45rem 0.6rem;
    font-size: 0.78rem;
  }
  .import-row {
    display: flex;
    align-items: center;
    gap: 0.55rem;
    flex-wrap: wrap;
  }
  .import-row .hint {
    color: #888;
    font-size: 0.74rem;
  }
  .row-actions {
    display: flex;
    gap: 0.35rem;
  }
  .empty {
    color: #888;
    font-style: italic;
    padding: 0.6rem 0.85rem;
    font-size: 0.85rem;
    background: #131318;
    border: 1px solid #1e1e25;
    border-radius: 6px;
  }
  table.peers {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.82rem;
    background: #131318;
    border: 1px solid #1e1e25;
    border-radius: 8px;
    overflow: hidden;
  }
  .peers thead th {
    text-align: left;
    color: #888;
    font-weight: 500;
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    padding: 0.45rem 0.7rem;
    border-bottom: 1px solid #1e1e25;
    background: #16161c;
  }
  .peers tbody td {
    padding: 0.55rem 0.7rem;
    border-bottom: 1px solid #1a1a20;
    vertical-align: top;
  }
  .peers tbody tr:last-child td {
    border-bottom: none;
  }
  .peer-label {
    font-weight: 500;
  }
  .peer-id {
    color: #777;
    font-size: 0.72rem;
  }
  .mono {
    font-family: ui-monospace, SFMono-Regular, monospace;
  }
  .role-cell {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
  }
  .role-menu {
    display: flex;
    gap: 0.2rem;
  }
  .role-opt {
    padding: 0.15rem 0.45rem;
    background: #1a1a22;
    border: 1px solid #2a2a35;
    border-radius: 3px;
    color: #888;
    cursor: pointer;
    font: inherit;
    font-size: 0.66rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .role-opt.active {
    color: #b8b8ff;
    border-color: #4a4a85;
    background: #1a1a2a;
  }
  .role-opt:hover:not(:disabled):not(.active) {
    border-color: #4a4a55;
    color: #e8e8e8;
  }
  .role-opt:disabled {
    opacity: 0.35;
    cursor: not-allowed;
  }
  .row-btn {
    padding: 0.25rem 0.6rem;
    background: #1a1a22;
    border: 1px solid #2a2a35;
    border-radius: 4px;
    color: #ccc;
    cursor: pointer;
    font: inherit;
    font-size: 0.74rem;
  }
  .row-btn.danger {
    color: #fca5a5;
    border-color: #4a2222;
  }
  .row-btn.danger:hover:not(:disabled) {
    background: #2a1414;
  }
  .row-btn:disabled {
    opacity: 0.5;
    cursor: default;
  }
</style>
