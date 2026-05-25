<script lang="ts">
  /** Approvals tab — the first thing a new user sees when they open
   *  Settings, because every cross-device peering starts here.
   *
   *  Pending approvals from across every joined network are flattened
   *  into a single chronological list so the user doesn't have to
   *  know which network a knocking peer is on to find them. Each row
   *  carries:
   *
   *   - the peer's self-reported label (cosmetic, not load-bearing),
   *   - a "suffix" tile with the 5-char display tag derived from the
   *     peer's pubkey — the stable per-device identifier users read
   *     aloud over voice ("ends in 7C4A1"),
   *   - a "code" tile with the 6-char verification code the peer
   *     generated this session — confirms freshness on top of the
   *     suffix's "right device" claim,
   *   - Approve / Deny actions, plus the network name so the user
   *     can see which mesh the request is on.
   *
   *  Mirrors MyOwnLLM's CloudMeshStatus "Network requests" block.
   *  Engine-side: every peer that hits `PendingApproval` shows up
   *  here until the user approves, denies, or the connection drops. */

  import { meshClient } from "../../mesh-client.svelte";
  import type { NetworkSummary, PeerInfo } from "../../types";
  import { networkDisplayName } from "../../types";

  type PendingRow = { network: NetworkSummary; peer: PeerInfo };

  /** Our own display suffix, derived from the daemon-reported
   *  `device_id`. Identity display IDs are `{pubkey}-{5-char hex}`
   *  (see `Identity::display_id` on the Rust side); we split on the
   *  last `-` and take the tail. Surfaced during approval so the
   *  user can read all four values back symmetrically — both
   *  suffixes and both codes — matching what the peer sees on their
   *  screen. */
  const ourSuffix = $derived.by(() => {
    const id = meshClient.identity?.device_id ?? "";
    const dash = id.lastIndexOf("-");
    if (dash === -1) return "";
    const tail = id.slice(dash + 1);
    if (tail.length === 5 && /^[0-9A-F]+$/.test(tail)) return tail;
    return "";
  });

  /** Flatten pending approvals across every joined network. We sort
   *  by network display name then label so a steady stream of
   *  requests stays visually anchored — new requests slot in where
   *  the eye expects them, not at the bottom in arrival order. */
  const pending = $derived<PendingRow[]>(
    meshClient.networks.flatMap((n) => {
      const peers = meshClient.peersByNetwork[n.config_id] ?? [];
      return peers
        .filter((p) => p.status === "pending_approval")
        .map((p) => ({ network: n, peer: p }));
    }),
  );

  let busyPeer = $state<string | null>(null);
  let actionError = $state<string | null>(null);

  async function approve(row: PendingRow) {
    busyPeer = row.peer.device_id;
    actionError = null;
    try {
      await meshClient.rosterApprove(
        row.network.config_id,
        row.peer.device_id,
        row.peer.label,
      );
    } catch (e) {
      actionError = String(e);
    } finally {
      busyPeer = null;
    }
  }

  async function deny(row: PendingRow) {
    busyPeer = row.peer.device_id;
    actionError = null;
    try {
      // Roster-remove on a pending peer drops the in-flight session
      // and refuses re-approval until the user explicitly approves
      // again. Same flow as the Remove action on already-approved
      // peers, but spelled "Deny" here so the affordance matches the
      // user's mental model of "I'm refusing this request."
      await meshClient.rosterRemove(row.network.config_id, row.peer.device_id);
    } catch (e) {
      actionError = String(e);
    } finally {
      busyPeer = null;
    }
  }

  function shortPubkey(id: string): string {
    if (id.length <= 14) return id;
    return `${id.slice(0, 10)}…${id.slice(-4)}`;
  }

  /** Bilateral-approval state per row. The engine keeps both halves
   *  (`local_approve_sent`, `remote_approve_seen`) and only flips
   *  status to Active when both are true — so a peer in
   *  pending_approval can be in three distinct sub-states the UI
   *  needs to render differently:
   *
   *   - fresh: neither side has approved yet. Show the full
   *     bilateral confirmation grid + Approve/Deny.
   *   - waiting-peer: we've approved, peer hasn't. Show "waiting
   *     for peer …" with a Revoke escape hatch (drops them from
   *     the roster and tears down).
   *   - confirm-needed: peer approved first, we haven't. Stronger
   *     callout ("peer authorised you — confirm to finish") plus
   *     the same confirmation tiles and Approve/Deny.
   *
   *   Inspired by MyOwnLLM's `approver_role` flag, which collapses
   *   the same two booleans into one. */
  function approvalState(p: PeerInfo): "fresh" | "waiting-peer" | "confirm-needed" {
    if (p.local_approve_sent && !p.remote_approve_seen) return "waiting-peer";
    if (!p.local_approve_sent && p.remote_approve_seen) return "confirm-needed";
    return "fresh";
  }
</script>

<div class="content">
  <div class="head">
    <h3>Pending approvals</h3>
    {#if pending.length > 0}
      <span class="count">{pending.length} waiting</span>
    {/if}
  </div>

  {#if actionError}
    <div class="err">⚠ {actionError}</div>
  {/if}

  {#if pending.length === 0}
    <div class="empty-state">
      <p class="empty-title">No pending approvals.</p>
      <p>
        To connect another device, open MyOwnMesh on it and join the
        same network — the daemon will surface a request here once
        the peer authenticates.
      </p>
      <ol>
        <li>
          On this device, make sure a network is joined (see <strong>Networks</strong>
          in the tab list to the left).
        </li>
        <li>
          On the other device, join the same network (same network ID, same
          signaling) — or import the exported settings from this device.
        </li>
        <li>
          When the peer authenticates, both sides see a request here. Approve
          when the <em>suffix</em> and <em>code</em> match what the other
          person reads out — that confirms you're talking to the right
          device, not a stranger who happens to be on the same network ID.
        </li>
      </ol>
    </div>
  {:else}
    <div class="hint">
      Read all four values back to the peer out-of-band before approving.
      Both sides see the same four — <strong>this device's</strong> suffix +
      code, the <strong>peer's</strong> suffix + code — so a true bilateral
      match confirms there's no impostor on either end. The peer must also
      approve on their side before the connection goes live.
    </div>
    <div class="list">
      {#each pending as row (row.peer.device_id + ":" + row.network.config_id)}
        {@const busy = busyPeer === row.peer.device_id}
        {@const state = approvalState(row.peer)}
        <div class="row" data-state={state}>
          <div class="row-head">
            <div class="label-line">
              <span class="peer-label">{row.peer.label || "Unnamed device"}</span>
              {#if row.peer.device_suffix}
                <span class="peer-suffix-inline">-{row.peer.device_suffix}</span>
              {/if}
              <span class="net-chip" title="Network this request is on">
                on <strong>{networkDisplayName(row.network)}</strong>
              </span>
              {#if state === "waiting-peer"}
                <span class="state-pill waiting" title="You approved this peer. The connection becomes live once they approve on their side.">
                  ✓ approved · waiting for peer
                </span>
              {:else if state === "confirm-needed"}
                <span class="state-pill confirm" title="The peer authorised the join from their side. Approve here to complete the handshake.">
                  peer authorised you · confirm
                </span>
              {/if}
            </div>
            <code class="pubkey" title={row.peer.device_id}>
              {shortPubkey(row.peer.device_id)}
            </code>
          </div>

          <!-- Bilateral confirmation grid: each side shows the same
               four values. The "ours" column is what THIS device
               reads to the peer; the "theirs" column is what the
               peer reads to us. Match all four out-of-band before
               approving. Blue tiles = stable per-device identity
               (suffix). Amber tiles = per-session freshness (code). -->
          <div class="confirm-grid">
            <div class="confirm-col">
              <div class="confirm-side-label">this device</div>
              <div class="confirm-pair">
                {#if ourSuffix}
                  <div
                    class="confirm-tile suffix-tile"
                    title="OUR stable display tag — derived from this device's pubkey. Read this aloud to the peer; they should see the same value in the 'peer' column on their screen."
                  >
                    <span class="confirm-label">suffix</span>
                    <span class="confirm-value">{ourSuffix}</span>
                  </div>
                {/if}
                {#if row.peer.verification_code_sent}
                  <div
                    class="confirm-tile code-tile"
                    title="OUR per-session verification code — generated freshly when this handshake started. Read this aloud to the peer; they should see the same value in their 'peer' column."
                  >
                    <span class="confirm-label">code</span>
                    <span class="confirm-value">{row.peer.verification_code_sent}</span>
                  </div>
                {/if}
              </div>
            </div>

            <div class="confirm-divider" aria-hidden="true">↔</div>

            <div class="confirm-col">
              <div class="confirm-side-label">peer</div>
              <div class="confirm-pair">
                {#if row.peer.device_suffix}
                  <div
                    class="confirm-tile suffix-tile"
                    title="PEER'S stable display tag — derived from their pubkey. Should match what they read aloud to you (in their 'this device' column)."
                  >
                    <span class="confirm-label">suffix</span>
                    <span class="confirm-value">{row.peer.device_suffix}</span>
                  </div>
                {/if}
                {#if row.peer.verification_code_received}
                  <div
                    class="confirm-tile code-tile"
                    title="PEER'S per-session verification code — generated when they started this handshake. Should match what they read aloud to you."
                  >
                    <span class="confirm-label">code</span>
                    <span class="confirm-value">{row.peer.verification_code_received}</span>
                  </div>
                {/if}
              </div>
            </div>
          </div>

          <div class="actions">
            {#if state === "waiting-peer"}
              <!-- We've already approved; the only useful action
                   left is to back out. Calling deny on an
                   already-approved peer revokes via the same
                   roster_remove path. -->
              <button class="btn ghost" disabled={busy} onclick={() => deny(row)}
                title="Revoke this approval and tear down the half-handshaken session.">
                Revoke
              </button>
            {:else}
              <button class="btn primary" disabled={busy} onclick={() => approve(row)}>
                {busy
                  ? "Approving…"
                  : state === "confirm-needed"
                    ? "Confirm"
                    : "Approve"}
              </button>
              <button class="btn ghost" disabled={busy} onclick={() => deny(row)}>
                Deny
              </button>
            {/if}
          </div>
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .content {
    flex: 1;
    overflow-y: auto;
    padding: 1rem 1.25rem;
    max-width: 50rem;
  }
  .head {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 0.75rem;
    margin-bottom: 0.75rem;
  }
  h3 {
    margin: 0;
    font-size: 0.92rem;
    font-weight: 600;
    color: #e8e8e8;
  }
  .count {
    font-size: 0.72rem;
    color: #ffd166;
    background: #2a2210;
    border: 1px solid #4a3a18;
    border-radius: 999px;
    padding: 0.1rem 0.5rem;
    font-family: ui-monospace, SFMono-Regular, monospace;
  }
  .err {
    background: #3a1717;
    color: #ffb4b4;
    border: 1px solid #5a2424;
    border-radius: 5px;
    padding: 0.45rem 0.6rem;
    font-size: 0.8rem;
    margin-bottom: 0.75rem;
  }
  .empty-state {
    background: #131318;
    border: 1px dashed #1e1e25;
    border-radius: 8px;
    padding: 0.95rem 1.1rem;
    color: #888;
    font-size: 0.82rem;
    line-height: 1.6;
    max-width: 42rem;
  }
  .empty-state p {
    margin: 0 0 0.5rem 0;
  }
  .empty-title {
    color: #ccc;
    font-weight: 600;
    margin-bottom: 0.55rem !important;
  }
  .empty-state ol {
    margin: 0.65rem 0 0 1.15rem;
    padding: 0;
  }
  .empty-state ol li {
    margin: 0.35rem 0;
  }
  .empty-state strong {
    color: #b8b8ff;
  }
  .empty-state em {
    color: #ffd166;
    font-style: normal;
    font-family: ui-monospace, SFMono-Regular, monospace;
    font-size: 0.78rem;
  }
  .hint {
    color: #b8b8b8;
    background: #1a1a22;
    border: 1px solid #2a2a35;
    border-radius: 6px;
    padding: 0.55rem 0.75rem;
    font-size: 0.78rem;
    line-height: 1.55;
    margin-bottom: 0.85rem;
    max-width: 42rem;
  }
  .hint strong {
    color: #ffd166;
    font-family: ui-monospace, SFMono-Regular, monospace;
    font-weight: 600;
    font-size: 0.76rem;
  }
  .list {
    display: flex;
    flex-direction: column;
    gap: 0.55rem;
  }
  .row {
    background: #131320;
    border: 1px solid #2a2a40;
    border-radius: 8px;
    padding: 0.75rem 0.9rem;
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }
  /* Already-approved-by-us: dim the row + green border so it
     visually settles into the background while the user waits on
     the peer. "confirm-needed" gets a louder amber border — the
     user needs to act, this should pull the eye. */
  .row[data-state="waiting-peer"] {
    border-color: #1c4a30;
    background: #0f1812;
  }
  .row[data-state="confirm-needed"] {
    border-color: #4a3a18;
    background: #1a1610;
  }
  .state-pill {
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    padding: 0.1rem 0.45rem;
    border-radius: 999px;
    font-family: ui-monospace, SFMono-Regular, monospace;
  }
  .state-pill.waiting {
    color: #b9f5cc;
    background: #112a1c;
    border: 1px solid #1c4a30;
  }
  .state-pill.confirm {
    color: #ffd166;
    background: #2a2210;
    border: 1px solid #4a3a18;
  }
  .row-head {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }
  .label-line {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
  }
  .peer-label {
    font-size: 0.92rem;
    font-weight: 600;
    color: #e8e8e8;
  }
  .peer-suffix-inline {
    font-family: ui-monospace, SFMono-Regular, monospace;
    font-size: 0.82rem;
    font-weight: 700;
    color: #b9c9ee;
    letter-spacing: 0.06em;
    user-select: all;
  }
  .net-chip {
    font-size: 0.72rem;
    color: #888;
  }
  .net-chip strong {
    color: #b8b8ff;
    font-weight: 600;
  }
  .pubkey {
    font-family: ui-monospace, SFMono-Regular, monospace;
    font-size: 0.68rem;
    color: #666;
    user-select: all;
  }
  /* Bilateral confirmation grid: two columns ("this device" and
     "peer"), each with a suffix + code tile pair, separated by a
     horizontal arrow to communicate "these should match across".
     Both peers see the same four values; that symmetry is the
     guarantee both sides are talking to the right device. */
  .confirm-grid {
    display: grid;
    grid-template-columns: 1fr auto 1fr;
    gap: 0.6rem;
    align-items: center;
    background: #0d0d12;
    border: 1px solid #1e1e25;
    border-radius: 7px;
    padding: 0.6rem 0.7rem;
  }
  .confirm-col {
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
    min-width: 0;
  }
  .confirm-side-label {
    font-size: 0.62rem;
    color: #888;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    text-align: center;
  }
  .confirm-pair {
    display: flex;
    gap: 0.45rem;
    flex-wrap: wrap;
    justify-content: center;
  }
  .confirm-divider {
    color: #555;
    font-size: 1.05rem;
    user-select: none;
    align-self: end;
    padding-bottom: 0.45rem;
  }
  /* Two tiles intentionally styled differently: suffix is the
     stable identity claim (blue), code is the per-session freshness
     proof (amber). The colour split helps users keep them straight
     when reading both aloud. */
  .confirm-tile {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    border-radius: 6px;
    padding: 0.32rem 0.8rem;
    min-width: 5.5rem;
  }
  .confirm-tile.suffix-tile {
    background: #131820;
    border: 1px solid #2a3a55;
  }
  .confirm-tile.code-tile {
    background: #2a2210;
    border: 1px solid #4a3a18;
  }
  .confirm-label {
    font-size: 0.58rem;
    text-transform: uppercase;
    letter-spacing: 0.09em;
    opacity: 0.6;
  }
  .confirm-tile.suffix-tile .confirm-label {
    color: #6a7a99;
  }
  .confirm-tile.code-tile .confirm-label {
    color: #a88d4a;
  }
  .confirm-value {
    font-family: ui-monospace, SFMono-Regular, monospace;
    font-size: 1.05rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    user-select: all;
  }
  .confirm-tile.suffix-tile .confirm-value {
    color: #b9c9ee;
  }
  .confirm-tile.code-tile .confirm-value {
    color: #ffd166;
  }
  .actions {
    display: flex;
    gap: 0.45rem;
  }
  .btn {
    font: inherit;
    font-size: 0.82rem;
    padding: 0.4rem 0.95rem;
    border-radius: 5px;
    cursor: pointer;
    border: 1px solid transparent;
  }
  .btn.primary {
    background: #5b4ad7;
    color: #fff;
    border-color: #6e5cf0;
    font-weight: 600;
  }
  .btn.primary:hover:not(:disabled) {
    background: #6e5cf0;
  }
  .btn.ghost {
    background: transparent;
    color: #c0b6e0;
    border-color: #3a2a55;
  }
  .btn.ghost:hover:not(:disabled) {
    background: #25193a;
    color: #fff;
  }
  .btn:disabled {
    opacity: 0.55;
    cursor: default;
  }
</style>
