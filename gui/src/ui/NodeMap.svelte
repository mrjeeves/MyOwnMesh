<script lang="ts">
  import type { AuthorizedPeer, NetworkSummary, PeerInfo, LinkKind } from "../types";
  import {
    linkKindOf,
    networkDisplayName,
    topologyName,
    topologyHub,
  } from "../types";
  import { meshClient } from "../mesh-client.svelte";

  const {
    network,
    peers,
    roster,
    networkChangeTs,
    selfDeviceId,
    selfLabel,
    selectedPeerId,
    onSelectPeer,
  }: {
    network: NetworkSummary;
    peers: PeerInfo[];
    /** On-disk authorised peers. Merged with `peers` so the graph
     *  always shows someone we've ever connected to, even if they
     *  aren't online or visible in signaling right now — once we've
     *  meshed with a device we know its id, we should be able to
     *  see it on the map. */
    roster: AuthorizedPeer[];
    /** Unix-ms timestamp of the most recent "primary network
     *  interface changed" diag for this network. Bumped from the
     *  mesh client; the self↔internet edge pulses for a few
     *  seconds afterwards so the user sees the engine noticed. */
    networkChangeTs: number;
    selfDeviceId: string;
    selfLabel: string;
    selectedPeerId: string | null;
    onSelectPeer: (id: string | null) => void;
  } = $props();

  /** Pending-action descriptor for a peer. `null` means there's
   *  nothing actionable about this peer right now. The `kind`
   *  picks which buttons render and what copy the description
   *  carries — the badge in the graph stays the same (a pending
   *  marker is a pending marker), but the popup needs to explain
   *  which half of the bilateral approval is missing.
   *
   *   - approve       — fresh: neither side has approved yet.
   *   - confirm       — peer approved first; user's confirm
   *                     completes the handshake.
   *   - waiting-peer  — user has already approved; nothing to do
   *                     but wait (or revoke). Buttons collapse to
   *                     just Revoke. */
  type PendingAction =
    | { kind: "approve"; description: string }
    | { kind: "confirm"; description: string }
    | { kind: "waiting-peer"; description: string }
    | null;

  function pendingActionFor(peer: PeerInfo | null): PendingAction {
    if (!peer) return null;
    if (peer.status !== "pending_approval") return null;
    if (peer.local_approve_sent && !peer.remote_approve_seen) {
      return {
        kind: "waiting-peer",
        description:
          "You approved this peer. The connection becomes live once they approve on their side.",
      };
    }
    if (!peer.local_approve_sent && peer.remote_approve_seen) {
      return {
        kind: "confirm",
        description:
          "The peer already approved you from their side. Confirm here to complete the handshake.",
      };
    }
    return {
      kind: "approve",
      description: "Peer authenticated — approve to start exchanging app traffic.",
    };
  }

  // Inline action state. Scoped to the currently-selected peer; we
  // reset both whenever the selection changes via the $effect below
  // so a stale error from one peer doesn't bleed into the next.
  let actionBusy = $state(false);
  let actionError = $state<string | null>(null);

  $effect(() => {
    // Reset action state when the selected peer changes.
    void selectedPeerId;
    actionBusy = false;
    actionError = null;
  });

  async function approveSelected() {
    if (!selectedPeer || actionBusy) return;
    actionBusy = true;
    actionError = null;
    try {
      await meshClient.rosterApprove(
        network.config_id,
        selectedPeer.device_id,
        selectedPeer.label,
      );
    } catch (e) {
      actionError = String(e);
    } finally {
      actionBusy = false;
    }
  }

  async function denySelected() {
    if (!selectedPeer || actionBusy) return;
    actionBusy = true;
    actionError = null;
    try {
      // Roster-remove on a not-yet-approved peer drops the in-flight
      // session and refuses re-approval until the user explicitly
      // approves again. Matches the Roster tab's Remove action.
      await meshClient.rosterRemove(network.config_id, selectedPeer.device_id);
      onSelectPeer(null);
    } catch (e) {
      actionError = String(e);
    } finally {
      actionBusy = false;
    }
  }

  // Canvas dimensions are reactive so the layout recomputes on
  // window resize. We track the SVG element's actual size via a
  // ResizeObserver rather than viewport units so the graph fits
  // its container (sidebar collapse, settings overlay close, etc.).
  let width = $state(800);
  let height = $state(600);
  let canvas: SVGSVGElement | null = $state(null);

  $effect(() => {
    if (!canvas) return;
    const ro = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const rect = entry.contentRect;
        width = Math.max(320, rect.width);
        height = Math.max(240, rect.height);
      }
    });
    ro.observe(canvas);
    return () => ro.disconnect();
  });

  /** Visible peers excluded from the graph. We keep peers that
   *  represent real engine state — sighted onward — and skip purely
   *  "offline" rows so the graph doesn't fill up with ghosts. The
   *  Connections settings panel lists them all. */
  const enginePeersForGraph = $derived(
    peers.filter(
      (p) => p.status !== "offline" || p.local_shelved || p.remote_shelved,
    ),
  );

  /** Synthetic peers for roster entries that aren't in the engine
   *  snapshot at all — peers we've meshed with before but who aren't
   *  currently visible on signaling. Rendered as dim "offline"
   *  nodes; the user knows the peer exists even when they're not
   *  around. Pubkey lookup matches `pubkey_part` on the Rust side:
   *  the roster stores the canonical pubkey, and PeerInfo.device_id
   *  is `{pubkey}-{suffix}`, so we compare on the pubkey prefix. */
  const rosteredOfflinePeers = $derived.by((): PeerInfo[] => {
    const knownPubkeys = new Set<string>();
    for (const p of peers) {
      knownPubkeys.add(pubkeyPart(p.device_id));
    }
    const synthetic: PeerInfo[] = [];
    for (const r of roster) {
      const pk = pubkeyPart(r.device_id);
      if (knownPubkeys.has(pk)) continue;
      synthetic.push({
        device_id: r.device_id,
        status: "offline",
        tier: "Steady",
        rtt_ms: null,
        label: r.label || "",
        capabilities: null,
        local_shelved: false,
        remote_shelved: false,
        authenticated: false,
        device_suffix: "",
        verification_code_received: null,
        verification_code_sent: null,
        local_approve_sent: false,
        remote_approve_seen: false,
        needs_turn: false,
        local_candidates: zeroCandidates(),
        remote_candidates: zeroCandidates(),
      });
    }
    return synthetic;
  });

  const visiblePeers = $derived([
    ...enginePeersForGraph,
    ...rosteredOfflinePeers,
  ]);

  function pubkeyPart(deviceId: string): string {
    const dash = deviceId.lastIndexOf("-");
    return dash === -1 ? deviceId : deviceId.slice(0, dash);
  }

  function zeroCandidates() {
    return { host: 0, server_reflexive: 0, peer_reflexive: 0, relay: 0, unknown: 0 };
  }

  type LaidOutNode = {
    id: string;
    label: string;
    x: number;
    y: number;
    role: "self" | "peer" | "hub" | "internet";
    peer: PeerInfo | null;
    /** Link-kind classification for peer nodes — drives colour and
     *  badge rendering. `null` for self / internet / hub roles. */
    link: LinkKind | null;
  };

  type LaidOutEdge = {
    from: string;
    to: string;
    /** Visual state of the edge. `active` / `shelved` / `transient`
     *  match the prior topology semantics for peer↔hub / peer↔self
     *  links; `internet`, `lan`, `stun`, `turn`, `blocked` capture
     *  the new link-kind routing (self↔internet, and any peer routed
     *  via internet vs. direct). */
    state:
      | "active"
      | "shelved"
      | "transient"
      | "internet"
      | "lan"
      | "stun"
      | "turn"
      | "blocked";
  };

  const INTERNET_NODE_ID = "__internet__";

  /** Compute (x,y) for every node + an edge list, based on the
   *  current topology AND each peer's link kind. Self sits at the
   *  centre as before; the Internet node hovers above. Peers whose
   *  data path goes through the public internet (STUN, TURN, or
   *  signaling-visible-but-unreachable) sit on a ring AROUND the
   *  Internet node and route through it; LAN peers (host↔host) sit
   *  on a ring around "you" directly. The topology selector still
   *  decides peer↔peer chord/ring decoration. Pure function of
   *  (peers, topology, width, height). */
  const layout = $derived.by((): { nodes: LaidOutNode[]; edges: LaidOutEdge[] } => {
    const cx = width / 2;
    const cy = height / 2 + 40; // shift self down to leave room for Internet above
    const topo = topologyName(network.topology);
    const hub = topologyHub(network.topology);

    const nodes: LaidOutNode[] = [];
    const edges: LaidOutEdge[] = [];

    const selfNode: LaidOutNode = {
      id: selfDeviceId || "__self__",
      label: selfLabel || "this device",
      x: cx,
      y: cy,
      role: "self",
      peer: null,
      link: null,
    };

    // Internet node — always rendered, sits above self. Position is
    // proportional to canvas height so it stays visually anchored
    // when the user resizes.
    const internetNode: LaidOutNode = {
      id: INTERNET_NODE_ID,
      label: "internet",
      x: cx,
      y: Math.max(50, cy - Math.min(width, height) / 2 + 10),
      role: "internet",
      peer: null,
      link: null,
    };
    nodes.push(internetNode);
    nodes.push(selfNode);
    edges.push({
      from: internetNode.id,
      to: selfNode.id,
      state: "internet",
    });

    if (visiblePeers.length === 0) {
      return { nodes, edges };
    }

    // Classify each peer's link kind. LAN peers sit on a ring
    // directly around self; everything else sits above on a ring
    // around the Internet node so the user can read "this peer
    // talks to me via the public internet" at a glance.
    const lanPeers: PeerInfo[] = [];
    const netPeers: PeerInfo[] = [];
    for (const p of visiblePeers) {
      const kind = linkKindOf(p);
      if (kind === "lan") lanPeers.push(p);
      else netPeers.push(p);
    }

    // Star topology: if the configured hub is one of the peers we
    // can see, anchor IT in the centre instead of self — same
    // behaviour as before so we don't regress the topology view.
    // The internet node still hovers above; LAN/external routing
    // still applies for non-hub peers.
    let centerNode: LaidOutNode = selfNode;
    if (topo === "star" && hub) {
      const hubPeer = visiblePeers.find((p) => p.device_id === hub);
      const weAreHub = hub === selfDeviceId;
      if (!weAreHub && hubPeer) {
        // Hub takes centre stage; remove from peer rings so it
        // isn't double-placed.
        const hubIdxLan = lanPeers.findIndex((p) => p.device_id === hub);
        if (hubIdxLan >= 0) lanPeers.splice(hubIdxLan, 1);
        const hubIdxNet = netPeers.findIndex((p) => p.device_id === hub);
        if (hubIdxNet >= 0) netPeers.splice(hubIdxNet, 1);
        centerNode = {
          id: hubPeer.device_id,
          label: hubPeer.label || shortId(hubPeer.device_id),
          x: cx,
          y: cy,
          role: "hub",
          peer: hubPeer,
          link: linkKindOf(hubPeer),
        };
        nodes.push(centerNode);
        edges.push({
          from: centerNode.id,
          to: selfNode.id,
          state: edgeStateFor(hubPeer),
        });
      }
    }

    // Lay out LAN peers around the centre. Small radius so they
    // visually cluster — "near" you in network terms.
    const lanRadius = Math.max(60, Math.min(width, height) / 5);
    placeOnArc(
      lanPeers,
      centerNode.x,
      centerNode.y,
      lanRadius,
      Math.PI * 0.25,
      Math.PI * 0.75,
      (node, peer) => {
        node.role = "peer";
        node.link = linkKindOf(peer);
        nodes.push(node);
        edges.push({
          from: centerNode.id,
          to: node.id,
          state: linkEdgeState(node.link, peer),
        });
      },
    );

    // Lay out internet-routed peers in a wider arc around the
    // Internet node. Includes anyone classified as stun/turn/blocked/unknown.
    const netRadius = Math.max(90, Math.min(width, height) / 3.2);
    placeOnArc(
      netPeers,
      internetNode.x,
      internetNode.y,
      netRadius,
      -Math.PI * 0.85,
      -Math.PI * 0.15,
      (node, peer) => {
        node.role = "peer";
        node.link = linkKindOf(peer);
        nodes.push(node);
        edges.push({
          from: internetNode.id,
          to: node.id,
          state: linkEdgeState(node.link, peer),
        });
      },
    );

    // Topology decoration on peer↔peer edges. Same caveat as
    // before: we don't actually know peer-to-peer link state from
    // here, the dashed edges are illustrative.
    if (topo === "full_mesh") {
      const peerNodes = nodes.filter((n) => n.role === "peer");
      for (let i = 0; i < peerNodes.length; i++) {
        for (let j = i + 1; j < peerNodes.length; j++) {
          edges.push({
            from: peerNodes[i].id,
            to: peerNodes[j].id,
            state: "transient",
          });
        }
      }
    } else if (topo === "ring") {
      const peerNodes = nodes.filter((n) => n.role === "peer");
      if (peerNodes.length > 2) {
        for (let i = 0; i < peerNodes.length; i++) {
          const next = peerNodes[(i + 1) % peerNodes.length];
          edges.push({
            from: peerNodes[i].id,
            to: next.id,
            state: "transient",
          });
        }
      }
    }

    return { nodes, edges };
  });

  /** Place peers on an arc and push the (mutable) `LaidOutNode`
   *  into the provided callback so the caller can finalise role /
   *  link / edges. We span an arc rather than a full ring so the
   *  LAN cluster (around self) and the external cluster (around
   *  internet) don't overlap visually. */
  function placeOnArc(
    list: PeerInfo[],
    cx: number,
    cy: number,
    radius: number,
    startAngle: number,
    endAngle: number,
    push: (node: LaidOutNode, peer: PeerInfo) => void,
  ) {
    if (list.length === 0) return;
    const span = endAngle - startAngle;
    const step = list.length === 1 ? 0 : span / (list.length - 1);
    list.forEach((p, i) => {
      const angle = startAngle + step * i;
      const node: LaidOutNode = {
        id: p.device_id,
        label: p.label || shortId(p.device_id),
        x: cx + Math.cos(angle) * radius,
        y: cy + Math.sin(angle) * radius,
        role: "peer",
        peer: p,
        link: null,
      };
      push(node, p);
    });
  }

  /** Map the inferred link kind to an edge state — but fall back
   *  to the standard active/shelved/transient when the peer is
   *  alive on a normal data path (so we don't paint everything as
   *  "lan/stun/turn" when the user is reading the green/yellow
   *  active/shelved language). */
  function linkEdgeState(link: LinkKind | null, peer: PeerInfo): LaidOutEdge["state"] {
    if (link === "blocked") return "blocked";
    if (link === "turn") return "turn";
    if (link === "stun") return "stun";
    if (link === "lan") return "lan";
    return edgeStateFor(peer);
  }

  function edgeStateFor(p: PeerInfo | null): "active" | "shelved" | "transient" {
    if (!p) return "transient";
    if (p.status === "active" && !p.local_shelved && !p.remote_shelved)
      return "active";
    if (
      p.status === "shelved" ||
      (p.status === "active" && (p.local_shelved || p.remote_shelved))
    )
      return "shelved";
    return "transient";
  }

  function shortId(id: string): string {
    if (id.length <= 12) return id;
    return id.slice(0, 6) + "…" + id.slice(-4);
  }

  function nodeColor(node: LaidOutNode): string {
    if (node.role === "self") return "#6e6ef7";
    if (!node.peer) return "#888";
    const p = node.peer;
    if (p.status === "active" && !p.local_shelved && !p.remote_shelved)
      return "#4ade80";
    if (p.status === "active") return "#facc15";
    if (p.status === "shelved") return "#facc15";
    if (p.status === "pending_approval") return "#a78bfa";
    if (p.status === "handshaking") return "#60a5fa";
    if (p.status === "sighted") return "#94a3b8";
    if (p.status === "reconnecting") return "#fb923c";
    if (p.status === "offline") return "#6b7280";
    if (p.status === "error") return "#ef4444";
    return "#888";
  }

  function edgeStroke(state: LaidOutEdge["state"]): string {
    switch (state) {
      case "active":
      case "lan":
        return "#4ade80";
      case "shelved":
        return "#6b7280";
      case "stun":
        return "#60a5fa";
      case "turn":
        return "#f59e0b";
      case "blocked":
        return "#ef4444";
      case "internet":
        return "#7d8aff";
      default:
        return "#2a2a3a";
    }
  }

  function edgeDash(state: LaidOutEdge["state"]): string | undefined {
    if (state === "transient" || state === "shelved") return "4 4";
    if (state === "turn" || state === "blocked" || state === "stun") return "5 4";
    return undefined;
  }

  function edgeOpacity(state: LaidOutEdge["state"]): number {
    if (state === "transient") return 0.45;
    if (state === "internet") return internetEdgeOpacity;
    return 0.9;
  }

  // ---- self↔internet edge pulse ---------------------------------------

  /** Wall-clock ms tracked reactively so the network-change pulse
   *  fades over a fixed window even when no other state updates. */
  let nowMs = $state(Date.now());
  $effect(() => {
    const t = setInterval(() => (nowMs = Date.now()), 250);
    return () => clearInterval(t);
  });

  const PULSE_WINDOW_MS = 4_000;

  const internetPulseActive = $derived(
    networkChangeTs > 0 && nowMs - networkChangeTs < PULSE_WINDOW_MS,
  );

  // Brighten the internet edge briefly after a network-change diag
  // so the user sees that the engine noticed. Outside the window it
  // sits at a calm default opacity.
  const internetEdgeOpacity = $derived(internetPulseActive ? 1 : 0.55);

  const selectedPeer = $derived(
    // Look across the merged set so clicking a roster-only / offline
    // node still surfaces its detail panel — selecting from the
    // engine-only list would return null for known-but-not-here peers.
    selectedPeerId
      ? visiblePeers.find((p) => p.device_id === selectedPeerId) ?? null
      : null,
  );

  /** This device's own display suffix, parsed from the daemon's
   *  `device_id` (which is `{pubkey}-{5-char hex}`; see
   *  `Identity::display_id` in the engine). Surfaced during pending
   *  approval so the popup shows both sides — ours + theirs — for
   *  bilateral confirmation. */
  const ourSuffix = $derived.by(() => {
    const id = meshClient.identity?.device_id ?? "";
    const dash = id.lastIndexOf("-");
    if (dash === -1) return "";
    const tail = id.slice(dash + 1);
    if (tail.length === 5 && /^[0-9A-F]+$/.test(tail)) return tail;
    return "";
  });
</script>

<div class="map">
  <div class="map-header">
    <div class="title">
      <span
        class="net"
        title="Network ID: {network.network_id}&#10;Local config id: {network.config_id}"
      >
        {networkDisplayName(network)}
      </span>
      <span class="topo">topology · {topologyName(network.topology)}</span>
    </div>
    <div class="legend">
      <span><span class="sw" style="background:#4ade80"></span> lan</span>
      <span><span class="sw sw-line" style="background:#60a5fa"></span> stun</span>
      <span><span class="sw sw-line" style="background:#f59e0b"></span> turn</span>
      <span><span class="sw sw-line" style="background:#ef4444"></span> needs turn</span>
      <span><span class="sw" style="background:#a78bfa"></span> pending</span>
      <span><span class="sw" style="background:#6b7280"></span> offline</span>
    </div>
  </div>

  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <svg
    bind:this={canvas}
    class="canvas"
    {width}
    {height}
    viewBox="0 0 {width} {height}"
    onclick={(e) => {
      if (e.target === e.currentTarget) onSelectPeer(null);
    }}
    role="img"
    aria-label="Mesh node graph"
  >
    <!-- Subtle dot grid in the background. Helps anchor the eye
         when nodes move and reinforces the canvas affordance. -->
    <defs>
      <pattern
        id="grid"
        width="32"
        height="32"
        patternUnits="userSpaceOnUse"
      >
        <circle cx="1" cy="1" r="1" fill="#1a1a1a" />
      </pattern>
    </defs>
    <rect x="0" y="0" {width} {height} fill="url(#grid)" />

    <!-- Edges. -->
    {#each layout.edges as edge}
      {@const a = layout.nodes.find((n) => n.id === edge.from)}
      {@const b = layout.nodes.find((n) => n.id === edge.to)}
      {#if a && b}
        <line
          x1={a.x}
          y1={a.y}
          x2={b.x}
          y2={b.y}
          stroke={edgeStroke(edge.state)}
          stroke-width={edge.state === "internet" && internetPulseActive ? 2.2 : 1.5}
          stroke-dasharray={edgeDash(edge.state)}
          opacity={edgeOpacity(edge.state)}
          class:internet-pulse={edge.state === "internet" && internetPulseActive}
        />
      {/if}
    {/each}

    <!-- Nodes. -->
    {#each layout.nodes as node}
      {@const selected = node.peer && node.peer.device_id === selectedPeerId}
      {@const offlineRoster =
        node.peer && node.peer.status === "offline" && node.role === "peer"}
      <!-- svelte-ignore a11y_click_events_have_key_events -->
      <g
        class="node"
        class:selected
        class:offline-roster={offlineRoster}
        class:internet={node.role === "internet"}
        transform="translate({node.x},{node.y})"
        onclick={(e) => {
          e.stopPropagation();
          if (node.peer) onSelectPeer(node.peer.device_id);
        }}
        onkeydown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            if (node.peer) onSelectPeer(node.peer.device_id);
          }
        }}
        role="button"
        tabindex={node.peer ? 0 : -1}
        aria-label={node.label}
      >
        {#if node.role === "internet"}
          <!-- Internet node: small cloud-ish capsule. Renders even
               when no peers are visible so the user always sees the
               link to the outside world. Stroke pulses with the
               edge when network_watch reports a change. -->
          <rect
            x="-34"
            y="-14"
            width="68"
            height="28"
            rx="14"
            ry="14"
            fill="#0d0d18"
            stroke={internetPulseActive ? "#a5b4ff" : "#5a6cd6"}
            stroke-width={internetPulseActive ? 2.2 : 1.5}
            class:internet-pulse={internetPulseActive}
          />
          <text y="4" text-anchor="middle" class="node-label internet-label">
            {node.label}
          </text>
        {:else if node.role === "self" || node.role === "hub"}
          <circle r="32" fill="#0d0d1a" stroke={nodeColor(node)} stroke-width="2" />
          <text y="-6" text-anchor="middle" class="node-role">
            {node.role === "self" ? "you" : "hub"}
          </text>
          <text y="9" text-anchor="middle" class="node-label">{node.label}</text>
        {:else}
          <circle r="22" fill="#0d0d0d" stroke={nodeColor(node)} stroke-width="2" />
          <text y="4" text-anchor="middle" class="node-label">{node.label}</text>
        {/if}
        {#if node.peer?.authenticated}
          <circle
            cx="16"
            cy="-16"
            r="4"
            fill="#0d0d0d"
            stroke="#4ade80"
            stroke-width="1.5"
          />
        {/if}
        {#if node.peer?.needs_turn}
          <!-- "Needs TURN" badge: small relay icon on the bottom-
               right. Tells the user at a glance that signaling has
               surfaced this peer but the data pipe is stuck because
               we can't reach them directly and there's no relay
               configured. The full diagnostic lands in the Activity
               log via the existing ICE diag. -->
          <g class="turn-badge" transform="translate(16, 16)">
            <circle r="7" fill="#0d0d0d" stroke="#f59e0b" stroke-width="1.5" />
            <text y="3" text-anchor="middle" class="turn-badge-glyph">⇆</text>
            <title>Needs TURN — direct connectivity blocked (symmetric NAT?)</title>
          </g>
        {/if}
        {#if pendingActionFor(node.peer)}
          <!-- Pending-action badge: pulsing ring + "!" glyph on the
               top-right of the node, mirroring the Approve / Deny
               row in the detail panel. Visible at a glance so the
               user knows which node needs them before drilling in. -->
          <circle
            class="pending-pulse"
            cx="-16"
            cy="-16"
            r="6"
            fill="#a78bfa"
            stroke="#0d0d0d"
            stroke-width="1.5"
          />
          <text
            x="-16"
            y="-13"
            text-anchor="middle"
            class="pending-badge-glyph"
          >
            !
          </text>
        {/if}
      </g>
    {/each}
  </svg>

  {#if selectedPeer}
    {@const pending = pendingActionFor(selectedPeer)}
    <div class="detail" role="dialog" aria-label="Peer detail">
      <div class="detail-head">
        <div class="detail-title">
          <span class="detail-label">
            {selectedPeer.label || shortId(selectedPeer.device_id)}
          </span>
          {#if selectedPeer.device_suffix}
            <!-- Inline suffix pill on the title row. Always visible
                 (not just during approval) so the user can read the
                 stable display tag back to a peer at any time —
                 picking the right device out of a crowded peers
                 list, debugging an approval mix-up, etc. -->
            <span class="detail-suffix" title="Stable display tag derived from the peer's pubkey">
              -{selectedPeer.device_suffix}
            </span>
          {/if}
        </div>
        <button
          class="close"
          onclick={() => onSelectPeer(null)}
          aria-label="Close detail"
        >
          ✕
        </button>
      </div>
      <div class="detail-id" title={selectedPeer.device_id}>
        {selectedPeer.device_id}
      </div>
      {#if pending}
        <div class="pending-action">
          <div class="pending-line">{pending.description}</div>
          {#if pending.kind === "approve" || pending.kind === "confirm"}
            <!-- Bilateral confirmation: shows both sides' suffix +
                 code so the user reads all four out-of-band before
                 approving. Mirrors the Approvals settings tab so
                 confirmation works the same way regardless of which
                 surface the user opens. -->
            <div class="confirm-grid">
              <div class="confirm-col">
                <div class="confirm-side-label">this device</div>
                <div class="confirm-pair">
                  {#if ourSuffix}
                    <div class="confirm-tile suffix-tile" title="OUR suffix — read aloud to the peer; they should see this in their 'peer' column.">
                      <span class="confirm-label">suffix</span>
                      <span class="confirm-value">{ourSuffix}</span>
                    </div>
                  {/if}
                  {#if selectedPeer.verification_code_sent}
                    <div class="confirm-tile code-tile" title="OUR per-session code — read aloud to the peer; they should see this in their 'peer' column.">
                      <span class="confirm-label">code</span>
                      <span class="confirm-value">{selectedPeer.verification_code_sent}</span>
                    </div>
                  {/if}
                </div>
              </div>
              <div class="confirm-divider" aria-hidden="true">↔</div>
              <div class="confirm-col">
                <div class="confirm-side-label">peer</div>
                <div class="confirm-pair">
                  {#if selectedPeer.device_suffix}
                    <div class="confirm-tile suffix-tile" title="PEER'S suffix — should match what they read aloud to you (in their 'this device' column).">
                      <span class="confirm-label">suffix</span>
                      <span class="confirm-value">{selectedPeer.device_suffix}</span>
                    </div>
                  {/if}
                  {#if selectedPeer.verification_code_received}
                    <div class="confirm-tile code-tile" title="PEER'S per-session code — should match what they read aloud to you.">
                      <span class="confirm-label">code</span>
                      <span class="confirm-value">{selectedPeer.verification_code_received}</span>
                    </div>
                  {/if}
                </div>
              </div>
            </div>
          {/if}
          {#if pending.kind === "waiting-peer"}
            <!-- Local approve already sent; only the revoke escape
                 hatch remains until the peer approves their side. -->
            <div class="pending-buttons">
              <button
                class="btn-deny"
                onclick={denySelected}
                disabled={actionBusy}
                title="Revoke this approval and tear down the half-handshaken session."
              >
                Revoke
              </button>
            </div>
          {:else if pending.kind === "approve" || pending.kind === "confirm"}
            <div class="pending-buttons">
              <button
                class="btn-approve"
                onclick={approveSelected}
                disabled={actionBusy}
              >
                {actionBusy
                  ? "Approving…"
                  : pending.kind === "confirm"
                    ? "Confirm"
                    : "Approve"}
              </button>
              <button
                class="btn-deny"
                onclick={denySelected}
                disabled={actionBusy}
              >
                Deny
              </button>
            </div>
          {/if}
          {#if actionError}
            <div class="pending-error">{actionError}</div>
          {/if}
        </div>
      {/if}
      <dl class="detail-grid">
        <dt>status</dt>
        <dd>{selectedPeer.status.replace("_", " ")}</dd>
        <dt>tier</dt>
        <dd>
          {typeof selectedPeer.tier === "string"
            ? selectedPeer.tier
            : Object.keys(selectedPeer.tier)[0]}
        </dd>
        <dt>auth</dt>
        <dd>{selectedPeer.authenticated ? "verified" : "—"}</dd>
        <dt>rtt</dt>
        <dd>{selectedPeer.rtt_ms == null ? "—" : selectedPeer.rtt_ms + " ms"}</dd>
        <dt>shelved</dt>
        <dd>
          {selectedPeer.local_shelved && selectedPeer.remote_shelved
            ? "both"
            : selectedPeer.local_shelved
              ? "by us"
              : selectedPeer.remote_shelved
                ? "by peer"
                : "—"}
        </dd>
        {#if selectedPeer.capabilities?.app_version}
          <dt>version</dt>
          <dd>{selectedPeer.capabilities.app_version}</dd>
        {/if}
        {#if selectedPeer.capabilities?.tags?.length}
          <dt>tags</dt>
          <dd>{selectedPeer.capabilities.tags.join(", ")}</dd>
        {/if}
      </dl>
    </div>
  {/if}
</div>

<style>
  .map {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-height: 0;
    position: relative;
  }
  .map-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    padding: 0.55rem 0.85rem;
    border-bottom: 1px solid #161616;
    background: rgba(10, 10, 10, 0.85);
    flex-shrink: 0;
    flex-wrap: wrap;
  }
  .title {
    display: flex;
    align-items: baseline;
    gap: 0.6rem;
  }
  .net {
    font-weight: 600;
    color: #e8e8e8;
  }
  .topo {
    font-size: 0.7rem;
    color: #888;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .legend {
    display: flex;
    gap: 0.85rem;
    color: #888;
    font-size: 0.7rem;
    flex-wrap: wrap;
  }
  .legend span {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
  }
  .sw {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    display: inline-block;
  }
  .canvas {
    flex: 1;
    display: block;
    width: 100%;
    height: 100%;
    min-height: 0;
  }
  .node {
    cursor: pointer;
    transition: filter 0.12s ease;
  }
  .node:hover circle {
    filter: brightness(1.18);
  }
  .node.selected circle {
    filter: drop-shadow(0 0 6px rgba(110, 110, 247, 0.7));
  }
  .node-label {
    fill: #e8e8e8;
    font-size: 10px;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    pointer-events: none;
  }
  .node-role {
    fill: #888;
    font-size: 8px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    pointer-events: none;
  }

  .detail {
    position: absolute;
    right: 1rem;
    bottom: 1rem;
    width: 22rem;
    max-width: calc(100% - 2rem);
    background: #131320;
    border: 1px solid #2a2a40;
    border-radius: 10px;
    padding: 0.85rem 1rem;
    box-shadow: 0 12px 32px rgba(0, 0, 0, 0.5);
    color: #e8e8e8;
  }
  .detail-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.5rem;
    margin-bottom: 0.25rem;
  }
  .detail-title {
    font-weight: 600;
    font-size: 0.92rem;
    display: flex;
    align-items: center;
    gap: 0.45rem;
    flex-wrap: wrap;
    min-width: 0;
  }
  .detail-label {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
  }
  /* Inline suffix pill — different shape from the approval tile
     below so the user reads "always-visible identifier" vs
     "actively-confirming for approval" at a glance. */
  .detail-suffix {
    font-family: ui-monospace, SFMono-Regular, monospace;
    font-size: 0.74rem;
    font-weight: 700;
    color: #b9c9ee;
    letter-spacing: 0.06em;
    background: #131820;
    border: 1px solid #2a3a55;
    border-radius: 4px;
    padding: 0.05rem 0.4rem;
    user-select: all;
  }
  .close {
    background: none;
    border: none;
    color: #888;
    cursor: pointer;
    padding: 0.15rem 0.3rem;
    border-radius: 4px;
    font-size: 0.85rem;
  }
  .close:hover {
    color: #e8e8e8;
    background: #1a1a2a;
  }
  .detail-id {
    font-family: ui-monospace, SFMono-Regular, monospace;
    font-size: 0.7rem;
    color: #888;
    word-break: break-all;
    margin-bottom: 0.7rem;
  }
  .detail-grid {
    display: grid;
    grid-template-columns: 5rem 1fr;
    gap: 0.25rem 0.6rem;
    font-size: 0.78rem;
  }
  .detail-grid dt {
    color: #888;
    text-transform: lowercase;
  }
  .detail-grid dd {
    color: #e0e0e0;
  }
  .pending-action {
    margin: 0.5rem 0 0.6rem 0;
    padding: 0.55rem 0.65rem;
    background: #1a1530;
    border: 1px solid #3a2a55;
    border-radius: 6px;
    display: flex;
    flex-direction: column;
    gap: 0.45rem;
  }
  .pending-line {
    font-size: 0.78rem;
    color: #d6c8ff;
    line-height: 1.4;
  }
  /* Bilateral confirmation grid: matches ApprovalsSection's
     layout so the user sees the same shape in both surfaces. Two
     columns ("this device" / "peer"), each a suffix + code pair,
     separated by a ↔ glyph that reads as "these should match". */
  .confirm-grid {
    display: grid;
    grid-template-columns: 1fr auto 1fr;
    gap: 0.45rem;
    align-items: center;
    background: #0d0d12;
    border: 1px solid #1e1e25;
    border-radius: 6px;
    padding: 0.45rem 0.55rem;
    margin: 0.1rem 0;
  }
  .confirm-col {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    min-width: 0;
  }
  .confirm-side-label {
    font-size: 0.58rem;
    color: #888;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    text-align: center;
  }
  .confirm-pair {
    display: flex;
    gap: 0.35rem;
    flex-wrap: wrap;
    justify-content: center;
  }
  .confirm-divider {
    color: #555;
    font-size: 0.95rem;
    user-select: none;
    align-self: end;
    padding-bottom: 0.35rem;
  }
  /* Mirrors ApprovalsSection's tile pair so the user reads the
     same confirmation in two places without re-learning the
     colour code. Blue = stable identity; amber = per-session
     freshness. */
  .confirm-tile {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    border-radius: 6px;
    padding: 0.28rem 0.7rem;
    min-width: 5rem;
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
    font-size: 0.55rem;
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
    font-size: 0.98rem;
    font-weight: 700;
    letter-spacing: 0.07em;
    user-select: all;
  }
  .confirm-tile.suffix-tile .confirm-value {
    color: #b9c9ee;
  }
  .confirm-tile.code-tile .confirm-value {
    color: #ffd166;
  }
  .pending-buttons {
    display: flex;
    gap: 0.4rem;
  }
  .btn-approve,
  .btn-deny {
    flex: 1;
    font: inherit;
    font-size: 0.78rem;
    padding: 0.3rem 0.55rem;
    border-radius: 5px;
    cursor: pointer;
    border: 1px solid transparent;
  }
  .btn-approve {
    background: #5b4ad7;
    color: #fff;
    border-color: #6e5cf0;
  }
  .btn-approve:hover:not(:disabled) {
    background: #6e5cf0;
  }
  .btn-deny {
    background: transparent;
    color: #c0b6e0;
    border-color: #3a2a55;
  }
  .btn-deny:hover:not(:disabled) {
    background: #25193a;
    color: #fff;
  }
  .btn-approve:disabled,
  .btn-deny:disabled {
    opacity: 0.55;
    cursor: default;
  }
  .pending-error {
    font-size: 0.72rem;
    color: #ffb4b4;
    font-family: ui-monospace, SFMono-Regular, monospace;
    word-break: break-word;
  }
  .pending-badge-glyph {
    fill: #0d0d0d;
    font-size: 9px;
    font-weight: 700;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    pointer-events: none;
    user-select: none;
  }
  .pending-pulse {
    animation: pending-pulse 1.6s ease-in-out infinite;
    transform-origin: center;
  }
  @keyframes pending-pulse {
    0%, 100% {
      opacity: 1;
      r: 6;
    }
    50% {
      opacity: 0.55;
      r: 7.5;
    }
  }

  /* Roster-only / offline peers: dim circle + greyed label so the
     user reads "known but not here" at a glance without the node
     competing with live peers for attention. */
  .node.offline-roster :global(circle) {
    opacity: 0.45;
  }
  .node.offline-roster :global(.node-label) {
    fill: #888;
  }

  .node.internet {
    cursor: default;
  }
  .node.internet:hover :global(rect) {
    filter: brightness(1.18);
  }
  .internet-label {
    fill: #b9c2ff;
    font-size: 9px;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    pointer-events: none;
  }
  /* Brief glow when network_watch detects a primary IP change.
     Mirrors the stroke-width bump set on the edge in markup so the
     two halves of the visual move together. */
  .internet-pulse {
    animation: internet-pulse 1.4s ease-in-out 2;
  }
  @keyframes internet-pulse {
    0%, 100% {
      filter: drop-shadow(0 0 0 rgba(165, 180, 255, 0));
    }
    50% {
      filter: drop-shadow(0 0 6px rgba(165, 180, 255, 0.85));
    }
  }

  .turn-badge {
    pointer-events: none;
  }
  .turn-badge-glyph {
    fill: #f59e0b;
    font-size: 8px;
    font-weight: 700;
    text-anchor: middle;
  }

  /* Solid swatch = node colour key; line swatch = edge-style key
     (so STUN/TURN/needs-turn read as edge types, not node states). */
  .sw-line {
    width: 14px;
    height: 2px;
    border-radius: 1px;
  }
</style>
