<script lang="ts">
  import type { NetworkSummary, PeerInfo } from "../types";
  import { topologyName, topologyHub } from "../types";

  const {
    network,
    peers,
    selfDeviceId,
    selfLabel,
    selectedPeerId,
    onSelectPeer,
  }: {
    network: NetworkSummary;
    peers: PeerInfo[];
    selfDeviceId: string;
    selfLabel: string;
    selectedPeerId: string | null;
    onSelectPeer: (id: string | null) => void;
  } = $props();

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
  const visiblePeers = $derived(
    peers.filter(
      (p) => p.status !== "offline" || p.local_shelved || p.remote_shelved,
    ),
  );

  type LaidOutNode = {
    id: string;
    label: string;
    x: number;
    y: number;
    role: "self" | "peer" | "hub";
    peer: PeerInfo | null;
  };

  type LaidOutEdge = {
    from: string;
    to: string;
    state: "active" | "shelved" | "transient";
  };

  /** Compute (x,y) for every node + an edge list, based on the
   *  current topology. Pure function of (peers, topology,
   *  width, height) — recomputes whenever any input changes. */
  const layout = $derived.by((): { nodes: LaidOutNode[]; edges: LaidOutEdge[] } => {
    const cx = width / 2;
    const cy = height / 2;
    const radius = Math.max(80, Math.min(width, height) / 2 - 90);
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
    };

    if (visiblePeers.length === 0) {
      nodes.push(selfNode);
      return { nodes, edges };
    }

    if (topo === "star" && hub) {
      // Star: hub at center, every other node on a ring around it.
      // If we are the hub, self stays in the middle; otherwise the
      // hub takes center stage and we sit on the ring.
      const peersOnRing: PeerInfo[] = [];
      let hubPeer: PeerInfo | null = null;
      for (const p of visiblePeers) {
        if (p.device_id === hub) hubPeer = p;
        else peersOnRing.push(p);
      }
      const weAreHub = hub === selfDeviceId;
      const centerNode: LaidOutNode = weAreHub
        ? selfNode
        : hubPeer
          ? {
              id: hubPeer.device_id,
              label: hubPeer.label || shortId(hubPeer.device_id),
              x: cx,
              y: cy,
              role: "hub",
              peer: hubPeer,
            }
          : selfNode;
      nodes.push(centerNode);

      const ringMembers: LaidOutNode[] = [];
      if (!weAreHub) {
        ringMembers.push({ ...selfNode, x: 0, y: 0 });
      }
      for (const p of peersOnRing) {
        ringMembers.push({
          id: p.device_id,
          label: p.label || shortId(p.device_id),
          x: 0,
          y: 0,
          role: "peer",
          peer: p,
        });
      }
      // Distribute around the circle.
      const total = ringMembers.length;
      ringMembers.forEach((node, i) => {
        const angle = (i / total) * Math.PI * 2 - Math.PI / 2;
        node.x = cx + Math.cos(angle) * radius;
        node.y = cy + Math.sin(angle) * radius;
        nodes.push(node);
        edges.push({
          from: centerNode.id,
          to: node.id,
          state: edgeStateFor(node.peer),
        });
      });
      return { nodes, edges };
    }

    // Ring / FullMesh / fallback: self in center, peers on a ring.
    nodes.push(selfNode);
    visiblePeers.forEach((p, i) => {
      const angle = (i / visiblePeers.length) * Math.PI * 2 - Math.PI / 2;
      const node: LaidOutNode = {
        id: p.device_id,
        label: p.label || shortId(p.device_id),
        x: cx + Math.cos(angle) * radius,
        y: cy + Math.sin(angle) * radius,
        role: "peer",
        peer: p,
      };
      nodes.push(node);
      edges.push({
        from: selfNode.id,
        to: node.id,
        state: edgeStateFor(p),
      });
    });

    if (topo === "full_mesh") {
      // Add peer-to-peer edges so the visualisation reflects the
      // shape. We treat them as "transient" since we don't actually
      // know peer-to-peer link state from here — the daemon only
      // surfaces our half of the mesh. The edges are decorative
      // but make the topology distinguishable from a ring at a
      // glance.
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
    } else if (topo === "ring" && nodes.length > 2) {
      // Decorative chord edges around the ring — peers route along
      // the ring in steady state. Same caveat as full-mesh: we
      // don't see the actual peer-to-peer link state.
      const peerNodes = nodes.filter((n) => n.role === "peer");
      for (let i = 0; i < peerNodes.length; i++) {
        const next = peerNodes[(i + 1) % peerNodes.length];
        edges.push({
          from: peerNodes[i].id,
          to: next.id,
          state: "transient",
        });
      }
    }

    return { nodes, edges };
  });

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
    if (state === "active") return "#4ade80";
    if (state === "shelved") return "#6b7280";
    return "#2a2a3a";
  }

  function edgeDash(state: LaidOutEdge["state"]): string | undefined {
    if (state === "transient" || state === "shelved") return "4 4";
    return undefined;
  }

  const selectedPeer = $derived(
    selectedPeerId ? peers.find((p) => p.device_id === selectedPeerId) ?? null : null,
  );
</script>

<div class="map">
  <div class="map-header">
    <div class="title">
      <span class="net">{network.config_id}</span>
      <span class="topo">topology · {topologyName(network.topology)}</span>
    </div>
    <div class="legend">
      <span><span class="sw" style="background:#4ade80"></span> active</span>
      <span><span class="sw" style="background:#facc15"></span> shelved</span>
      <span><span class="sw" style="background:#a78bfa"></span> pending</span>
      <span><span class="sw" style="background:#60a5fa"></span> handshaking</span>
      <span><span class="sw" style="background:#94a3b8"></span> sighted</span>
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
          stroke-width="1.5"
          stroke-dasharray={edgeDash(edge.state)}
          opacity={edge.state === "transient" ? 0.45 : 0.9}
        />
      {/if}
    {/each}

    <!-- Nodes. -->
    {#each layout.nodes as node}
      {@const selected = node.peer && node.peer.device_id === selectedPeerId}
      <!-- svelte-ignore a11y_click_events_have_key_events -->
      <g
        class="node"
        class:selected
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
        tabindex="0"
        aria-label={node.label}
      >
        {#if node.role === "self" || node.role === "hub"}
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
      </g>
    {/each}
  </svg>

  {#if selectedPeer}
    <div class="detail" role="dialog" aria-label="Peer detail">
      <div class="detail-head">
        <div class="detail-title">
          {selectedPeer.label || shortId(selectedPeer.device_id)}
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
</style>
