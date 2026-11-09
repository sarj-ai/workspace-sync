import "@xyflow/react/dist/style.css";

import {
  Background,
  Controls,
  MarkerType,
  Position,
  ReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";

import { architecture } from "../lib/architecture.ts";

const NODES: Node[] = architecture.nodes.map((node) => ({
  id: node.id,
  position: { x: node.x, y: node.y },
  className: `flow-node flow-node-${node.kind}`,
  sourcePosition:
    node.id === "write" || node.id === "review"
      ? Position.Bottom
      : node.id === "replan" || node.id === "budget"
        ? Position.Left
        : Position.Right,
  targetPosition:
    node.id === "replan" || node.id === "readback"
      ? Position.Top
      : node.id === "budget" || node.id === "write"
        ? Position.Right
        : Position.Left,
  data: {
    label: (
      <>
        <strong>{node.label}</strong>
        <span>{node.detail}</span>
      </>
    ),
  },
}));
const EDGES: Edge[] = architecture.edges.map((edge) => ({
  id: `${edge.source}-${edge.target}`,
  ...edge,
  type: "smoothstep",
  markerEnd: { type: MarkerType.ArrowClosed },
}));

export default function ArchitectureFlow() {
  return (
    <div
      className="architecture-flow not-content"
      role="region"
      aria-label="Workspace Sync data flow"
    >
      <ReactFlow
        nodes={NODES}
        edges={EDGES}
        nodesDraggable={false}
        nodesConnectable={false}
        edgesFocusable={false}
        zoomOnScroll={false}
        preventScrolling={false}
        fitView
        fitViewOptions={{ padding: 0.15 }}
        minZoom={0.2}
        maxZoom={1.5}
      >
        <Background gap={22} size={1} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
