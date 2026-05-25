<script lang="ts">
  /** Padlock badge for a network's governance kind — `open` shows an
   *  unlocked outline, `closed` shows a filled lock. Used wherever a
   *  network name renders so the kind is always one glance away from
   *  the user (sidebar row, overlay header, status card, graph). */
  import type { NetworkKind } from "../../types";

  const {
    kind,
    size = 14,
    showLabel = false,
    tooltip,
  }: {
    kind: NetworkKind;
    size?: number;
    showLabel?: boolean;
    tooltip?: string;
  } = $props();

  const title = $derived(
    tooltip ??
      (kind === "closed"
        ? "Closed network — role-based authority on the roster."
        : "Open network — any member can add to the roster."),
  );
</script>

<span class="kind-badge" data-kind={kind} {title}>
  {#if kind === "closed"}
    <!-- Filled padlock -->
    <svg viewBox="0 0 24 24" width={size} height={size} aria-hidden="true">
      <path
        fill="currentColor"
        d="M7 10V7a5 5 0 0 1 10 0v3h1a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2h1zm2 0h6V7a3 3 0 0 0-6 0v3z"
      />
    </svg>
  {:else}
    <!-- Open padlock outline -->
    <svg viewBox="0 0 24 24" width={size} height={size} aria-hidden="true">
      <path
        fill="none"
        stroke="currentColor"
        stroke-width="2"
        stroke-linejoin="round"
        d="M7 10V7a5 5 0 0 1 9.6-2M6 10h12a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2z"
      />
    </svg>
  {/if}
  {#if showLabel}
    <span class="kind-label">{kind}</span>
  {/if}
</span>

<style>
  .kind-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    line-height: 0;
    color: #94a3b8;
  }
  .kind-badge[data-kind="closed"] {
    color: #fbbf24;
  }
  .kind-label {
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    line-height: 1;
    color: inherit;
  }
</style>
