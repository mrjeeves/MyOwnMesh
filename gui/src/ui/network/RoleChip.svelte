<script lang="ts">
  /** Compact chip showing a peer's role in a closed network. Three
   *  colour-coded levels: owner (amber, can do anything),
   *  controller (blue, can add members), member (grey, no roster
   *  authority). Used in the Roster table + Connections list. */
  import { roleColor, type Role } from "../../types";

  const {
    role,
    size = "sm",
    title,
  }: {
    role: Role;
    size?: "xs" | "sm" | "md";
    title?: string;
  } = $props();
</script>

<span
  class="role-chip"
  data-role={role}
  data-size={size}
  title={title ?? `Role: ${role}`}
  style="--role-color: {roleColor(role)}"
>
  {role}
</span>

<style>
  .role-chip {
    display: inline-flex;
    align-items: center;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--role-color);
    background: color-mix(in srgb, var(--role-color) 12%, #131318);
    border: 1px solid color-mix(in srgb, var(--role-color) 32%, #131318);
    border-radius: 999px;
    line-height: 1;
    white-space: nowrap;
  }
  .role-chip[data-size="xs"] {
    font-size: 0.6rem;
    padding: 0.08rem 0.4rem;
  }
  .role-chip[data-size="sm"] {
    font-size: 0.66rem;
    padding: 0.1rem 0.5rem;
  }
  .role-chip[data-size="md"] {
    font-size: 0.74rem;
    padding: 0.18rem 0.6rem;
  }
</style>
