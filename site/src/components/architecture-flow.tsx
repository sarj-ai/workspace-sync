import {
  Background,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
  type ReactFlowInstance,
} from "@xyflow/react";
import { useEffect, useRef, useState } from "react";

import {
  apiHref,
  integrationById,
  integrations,
  providerIcon,
  workflowFor,
  workflowEdges,
  type FlowStage,
  type IntegrationId,
} from "../lib/architecture.ts";

type StageNode = Node<
  {
    stage: FlowStage;
    number: number;
    active: boolean;
    select: () => void;
  },
  "stage"
>;

function Stage({ data }: NodeProps<StageNode>) {
  return (
    <>
      {Object.values(Position).map((position) => (
        <Handle
          key={`in-${position}`}
          type="target"
          position={position}
          id={`in-${position}`}
        />
      ))}
      <button
        type="button"
        className="flow-stage nodrag nopan"
        aria-pressed={data.active}
        aria-controls="architecture-explanation"
        onClick={data.select}
        onFocus={data.select}
        data-flow-step={data.stage.id}
      >
        <span className="flow-stage-number">{data.number}</span>
        {data.stage.icon !== null && (
          <img
            src={providerIcon(data.stage.icon)}
            alt=""
            width="28"
            height="28"
            draggable={false}
          />
        )}
        <strong>{data.stage.label}</strong>
        <span className="flow-stage-detail">{data.stage.detail}</span>
      </button>
      {Object.values(Position).map((position) => (
        <Handle
          key={`out-${position}`}
          type="source"
          position={position}
          id={`out-${position}`}
        />
      ))}
    </>
  );
}

const NODE_TYPES = { stage: Stage } as const;
const POSITIONS = [
  { x: 0, y: 0 },
  { x: 300, y: 0 },
  { x: 600, y: 0 },
  { x: 900, y: 0 },
  { x: 900, y: 260 },
  { x: 600, y: 260 },
] as const;
const GITHUB_POSITIONS = [
  { x: 0, y: 0 },
  { x: 0, y: 260 },
  { x: 300, y: 130 },
  { x: 600, y: 130 },
] as const;

function arrangeViewport(
  flow: ReactFlowInstance<StageNode>,
  canvas: HTMLDivElement,
): void {
  const nodes = flow.getNodes();
  const active = nodes.find((node) => node.data.active) ?? nodes[0];
  if (!active) return;
  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  const graphWidth = Math.max(...nodes.map((node) => node.position.x)) + 224;
  const graphHeight = Math.max(...nodes.map((node) => node.position.y)) + 164;
  const zoom = width < 900 ? 1 : Math.min(1, (width - 64) / graphWidth);
  flow
    .setViewport(
      width < 900
        ? {
            x: width / 2 - (active.position.x + 112),
            y: height / 2 - (active.position.y + 82),
            zoom,
          }
        : {
            x: (width - graphWidth * zoom) / 2,
            y: (height - graphHeight * zoom) / 2,
            zoom,
          },
    )
    .catch(reportError);
}

export default function ArchitectureFlow() {
  const [integration, setIntegration] = useState<IntegrationId>("slack");
  const [step, setStep] = useState(1);
  const [instance, setInstance] = useState<ReactFlowInstance<StageNode> | null>(
    null,
  );
  const canvas = useRef<HTMLDivElement>(null);
  const stages = workflowFor(integration);
  const provider = integrationById(integration);
  const positions = integration === "github" ? GITHUB_POSITIONS : POSITIONS;
  useEffect(() => {
    const element = canvas.current;
    if (!element || !instance) return;
    const observer = new ResizeObserver(() =>
      arrangeViewport(instance, element),
    );
    observer.observe(element);
    return () => observer.disconnect();
  }, [instance]);
  const selected = stages[step];
  const selectStep = (index: number): void => {
    if (index < 0 || index >= stages.length) return;
    setStep(index);
    const position = positions[index];
    if (position && canvas.current && canvas.current.clientWidth < 900) {
      instance
        ?.setCenter(position.x + 112, position.y + 82, { zoom: 1 })
        .catch(reportError);
    }
  };
  const nodes: StageNode[] = stages.map((stage, index) => ({
    id: stage.id,
    type: "stage",
    position: positions[index] ?? { x: 0, y: 0 },
    initialWidth: 224,
    initialHeight: 164,
    className: `flow-node flow-node-${stage.kind}${index === step ? " is-active" : ""}`,
    data: {
      stage,
      number: index + 1,
      active: index === step,
      select: () => selectStep(index),
    },
  }));
  const edges: Edge[] = workflowEdges(integration).map((edge) => {
    const from = positions[edge.from];
    const to = positions[edge.to];
    const vertical = from?.x === to?.x;
    const backwards = from && to && from.x > to.x;
    return {
      id: `${edge.source}-${edge.target}`,
      source: edge.source,
      target: edge.target,
      sourceHandle: `out-${vertical ? "bottom" : backwards ? "left" : "right"}`,
      targetHandle: `in-${vertical ? "top" : backwards ? "right" : "left"}`,
      type: "straight",
      markerEnd: { type: MarkerType.ArrowClosed, width: 18, height: 18 },
      className: edge.to <= step ? "flow-edge-travelled" : "",
      label: edge.label,
      labelStyle: { fontSize: 12, fontWeight: 650 },
      labelBgPadding: [6, 4],
      labelBgBorderRadius: 4,
    };
  });
  const chooseIntegration = (id: IntegrationId): void => {
    setIntegration(id);
    setStep(0);
  };
  if (!selected) return null;

  return (
    <section
      className="architecture-explorer not-content"
      aria-label="Interactive architecture walkthrough"
    >
      <div className="flow-toolbar">
        <div>
          <h2>Follow a workflow</h2>
          <p>Choose an integration, then click a node to see what happens.</p>
        </div>
        <span className="flow-mode">
          {integration === "github"
            ? "Read-only audit"
            : integration === "attio"
              ? "Snapshot refresh"
              : "Plan → review → apply"}
        </span>
      </div>
      <div
        className="flow-integrations"
        role="group"
        aria-label="Choose an integration"
      >
        {integrations.map((item) => (
          <button
            key={item.id}
            type="button"
            aria-pressed={item.id === integration}
            onClick={() => chooseIntegration(item.id)}
          >
            <img src={providerIcon(item.icon)} alt="" width="20" height="20" />
            {item.label}
          </button>
        ))}
      </div>
      <div
        ref={canvas}
        className="architecture-flow"
        role="region"
        aria-label={`${provider.label} workflow diagram`}
      >
        <ReactFlow<StageNode>
          key={integration}
          nodes={nodes}
          edges={edges}
          nodeTypes={NODE_TYPES}
          onInit={setInstance}
          nodesDraggable={false}
          nodesConnectable={false}
          nodesFocusable={false}
          edgesFocusable={false}
          zoomOnScroll={false}
          zoomOnDoubleClick={false}
          preventScrolling={false}
          defaultViewport={{ x: 32, y: 100, zoom: 1 }}
          minZoom={0.25}
          maxZoom={1.75}
          ariaLabelConfig={{
            "controls.zoomIn.ariaLabel": "Zoom in",
            "controls.zoomOut.ariaLabel": "Zoom out",
            "controls.fitView.ariaLabel": "Fit workflow",
          }}
        >
          <Background gap={24} size={1} />
          <Controls
            showInteractive={false}
            fitViewOptions={{ padding: 0.1, maxZoom: 1 }}
          />
        </ReactFlow>
        <span className="flow-canvas-hint">
          Drag to pan · Pinch or use + / − to zoom
        </span>
      </div>
      <nav className="flow-stepper" aria-label="Workflow steps">
        {stages.map((stage, index) => (
          <button
            key={stage.id}
            type="button"
            aria-current={step === index ? "step" : undefined}
            aria-controls="architecture-explanation"
            onClick={() => selectStep(index)}
          >
            <span>{index + 1}</span>
            {stage.label}
          </button>
        ))}
      </nav>
      <section
        className="flow-explanation"
        id="architecture-explanation"
        aria-labelledby="flow-detail-title"
      >
        <header className="flow-detail-header">
          <div aria-live="polite" aria-atomic="true">
            <p className="flow-eyebrow">
              {provider.label} · Step {step + 1} of {stages.length}
            </p>
            <h3 id="flow-detail-title">{selected.label}</h3>
          </div>
          <div className="flow-step-actions">
            <button
              type="button"
              disabled={step === 0}
              onClick={() => selectStep(step - 1)}
              aria-label="Previous step"
            >
              ← Previous
            </button>
            <button
              type="button"
              disabled={step === stages.length - 1}
              onClick={() => selectStep(step + 1)}
              aria-label="Next step"
            >
              Next →
            </button>
          </div>
        </header>
        <div className="flow-detail-grid">
          <div>
            <h4>What comes in</h4>
            <p>{selected.input}</p>
          </div>
          <div>
            <h4>What happens</h4>
            <ol>
              {selected.actions.map((action) => (
                <li key={action}>{action}</li>
              ))}
            </ol>
          </div>
          <div>
            <h4>What comes out</h4>
            <p>{selected.output}</p>
          </div>
        </div>
        <p className="flow-guard">
          <strong>Check:</strong> {selected.guard}
        </p>
        <footer>
          <a href={apiHref(selected.module)}>Open API reference →</a>
          <span>Diagram only · No accounts are connected</span>
        </footer>
      </section>
    </section>
  );
}
