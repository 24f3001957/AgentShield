import {
  Background,
  BaseEdge,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  getBezierPath,
  type Edge,
  type EdgeProps,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import { useMemo } from "react";
import { Link } from "react-router-dom";
import type { SimulationResult } from "../lib/types";
import { Badge, DecisionBadge, Hash, JsonBlock } from "./ui";

type PipelineState =
  | "idle"
  | "processing"
  | "allowed"
  | "approval"
  | "denied"
  | "executed"
  | "verified"
  | "failed";

const STATE_LABEL: Record<PipelineState, string> = {
  idle: "idle",
  processing: "processing",
  allowed: "allowed",
  approval: "approval required",
  denied: "denied",
  executed: "executed",
  verified: "verified",
  failed: "failed",
};

const NODE_TONE: Record<PipelineState, string> = {
  idle: "muted",
  processing: "blue",
  allowed: "teal",
  approval: "amber",
  denied: "coral",
  executed: "teal",
  verified: "purple",
  failed: "coral",
};

type PipelineNodeData = {
  title: string;
  subtitle: string;
  glyph: string;
  state: PipelineState;
  detail?: string;
};

type PipelineNode = Node<PipelineNodeData, "pipeline">;

const NODE_TYPES = { pipeline: PipelineNodeView };

const NODE_SPECS = [
  { id: "agent", title: "AI Agent", subtitle: "proposes a tool call", glyph: "◈", x: 0, y: 150 },
  { id: "gateway", title: "Security Gateway", subtitle: "Gateway.submit", glyph: "▣", x: 240, y: 150 },
  { id: "validator", title: "Request Validator", subtitle: "schema · registry · paths", glyph: "⌗", x: 480, y: 150 },
  { id: "policy", title: "Policy Engine", subtitle: "ordered, first-match-wins", glyph: "⚖", x: 720, y: 150 },
  { id: "approval", title: "Approval Service", subtitle: "bound human decision", glyph: "⏸", x: 960, y: 300 },
  { id: "authorization", title: "Authorization", subtitle: "HMAC, single use", glyph: "✶", x: 960, y: 20 },
  { id: "executor", title: "Controlled Executor", subtitle: "re-verifies, then runs", glyph: "▶", x: 1200, y: 20 },
  { id: "audit_writer", title: "Audit Writer", subtitle: "SHA-256 hash chain", glyph: "⛓", x: 1440, y: 150 },
  { id: "audit_verifier", title: "Audit Verifier", subtitle: "recomputes the chain", glyph: "✓", x: 1680, y: 150 },
] as const;

const EDGE_SPECS: Array<{
  id: string;
  source: string;
  target: string;
  tone: string;
  kind: "main" | "approval";
}> = [
  { id: "e-agent", source: "agent", target: "gateway", tone: "blue", kind: "main" },
  { id: "e-gateway", source: "gateway", target: "validator", tone: "blue", kind: "main" },
  { id: "e-validator", source: "validator", target: "policy", tone: "blue", kind: "main" },
  { id: "e-approval", source: "policy", target: "approval", tone: "amber", kind: "approval" },
  { id: "e-approve-auth", source: "approval", target: "authorization", tone: "amber", kind: "approval" },
  { id: "e-allow", source: "policy", target: "authorization", tone: "teal", kind: "main" },
  { id: "e-authz", source: "authorization", target: "executor", tone: "teal", kind: "main" },
  { id: "e-exec", source: "executor", target: "audit_writer", tone: "teal", kind: "main" },
  { id: "e-verify", source: "audit_writer", target: "audit_verifier", tone: "purple", kind: "main" },
];

const TONE_HEX: Record<string, string> = {
  teal: "#55d6be",
  blue: "#79afff",
  amber: "#f5be67",
  coral: "#ff8585",
  purple: "#d0a7ff",
  muted: "#46587a",
};

function PipelineNodeView({ data }: NodeProps<PipelineNode>) {
  return (
    <div className={`pipeline-node pipeline-node--${NODE_TONE[data.state]}`}>
      <Handle type="target" position={Position.Left} className="graph-handle" />
      <div className="pipeline-node-head">
        <span className="pipeline-glyph" aria-hidden="true">
          {data.glyph}
        </span>
        <span className="pipeline-title">{data.title}</span>
      </div>
      <p className="pipeline-subtitle">{data.subtitle}</p>
      <p className="pipeline-state">
        <span className={`dot dot--${NODE_TONE[data.state]}`} aria-hidden="true" />
        {STATE_LABEL[data.state]}
      </p>
      {data.detail ? <p className="pipeline-detail">{data.detail}</p> : null}
      <Handle type="source" position={Position.Right} className="graph-handle" />
    </div>
  );
}

type ParticleEdgeData = { active: boolean; delay: number; tone: string };

function ParticleEdge({
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
  markerEnd,
}: EdgeProps) {
  const [path] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });
  const payload = (data ?? {}) as ParticleEdgeData;
  const color = TONE_HEX[payload.tone] ?? TONE_HEX.muted;
  return (
    <>
      <BaseEdge
        path={path}
        markerEnd={markerEnd}
        style={{
          stroke: color,
          strokeWidth: payload.active ? 2 : 1.2,
          opacity: payload.active ? 0.9 : 0.28,
          strokeDasharray: payload.active ? "6 4" : undefined,
          animation: payload.active ? "dash-flow 1.2s linear infinite" : undefined,
        }}
      />
      {payload.active ? (
        <circle r={3.4} fill={color} className="flow-particle">
          <animateMotion
            dur="1.1s"
            begin={`${payload.delay}ms`}
            repeatCount="indefinite"
            path={path}
          />
        </circle>
      ) : null}
    </>
  );
}

const EDGE_TYPES = { particle: ParticleEdge };

type Derived = {
  states: Record<string, { state: PipelineState; detail?: string }>;
  activeEdges: Record<string, { delay: number; tone: string }>;
  order: string[];
};

export function derivePipeline(run: SimulationResult | null): Derived {
  const states: Derived["states"] = {};
  for (const spec of NODE_SPECS) states[spec.id] = { state: "idle" };
  if (!run) return { states, activeEdges: {}, order: [] };

  const events = run.steps.flatMap((step) => step.audit_events);
  const types = new Set(events.map((event) => event.event_type));
  const decisions = events
    .filter((event) => event.event_type === "policy_decision")
    .map((event) => `${String(event.payload.decision)} ${String(event.payload.reason_code ?? "")}`);

  const allowed = run.steps.some((step) => step.response.decision === "ALLOW");
  const denied = run.result.decision === "DENY";
  const awaiting = run.result.decision === "APPROVAL";
  const executed = types.has("execution_started") || types.has("execution_completed");

  states.agent = { state: "processing", detail: "intent submitted" };
  states.gateway = { state: "processing", detail: `${run.steps.length} calls received` };
  states.validator = { state: "allowed", detail: "schema + registry passed" };
  states.policy = {
    state: denied ? "denied" : awaiting ? "approval" : allowed ? "allowed" : "processing",
    detail: decisions.join(" · ") || undefined,
  };
  if (types.has("approval_created")) {
    states.approval = { state: "approval", detail: "pending bound decision" };
  }
  states.authorization = types.has("authorization_issued")
    ? { state: "allowed", detail: "issued once" }
    : { state: "idle", detail: "not reached" };
  states.executor = executed
    ? {
        state: "executed",
        detail: denied ? "ran step 1 only (read)" : "mock tool ran",
      }
    : { state: "idle", detail: "never reached" };
  states.audit_writer = events.some((event) =>
    ["provenance_recorded", "execution_completed", "execution_recorded"].includes(
      event.event_type,
    ),
  )
    ? { state: "processing", detail: `${events.length} events written` }
    : { state: "idle" };
  states.audit_verifier = types.has("audit_verification")
    ? { state: "verified" }
    : { state: "idle", detail: "not run in this scenario" };

  const activeEdges: Derived["activeEdges"] = {};
  const order: string[] = [];
  let step = 0;
  const hop = (edgeId: string, tone: string) => {
    activeEdges[edgeId] = { delay: step * 780, tone };
    order.push(edgeId);
    step += 1;
  };

  // The particle trail follows the final step - the attack itself. Earlier
  // steps (the confidential read) are reflected in the node states and the
  // step table, never invented movement.
  hop("e-agent", "blue");
  hop("e-gateway", "blue");
  hop("e-validator", "blue");
  if (denied) {
    // Stops at the policy engine: no edge is lit past it.
  } else if (awaiting) {
    hop("e-approval", "amber");
  } else {
    hop("e-allow", "teal");
    hop("e-authz", "teal");
    hop("e-exec", "teal");
  }
  return { states, activeEdges, order };
}

export function PipelineGraph({
  run,
  onRun,
  busy,
  error,
  replay,
}: {
  run: SimulationResult | null;
  onRun: () => void;
  busy: boolean;
  error: string | null;
  replay: number;
}) {
  const derived = useMemo(() => derivePipeline(run), [run]);

  const nodes: PipelineNode[] = useMemo(
    () =>
      NODE_SPECS.map((spec) => ({
        id: spec.id,
        type: "pipeline" as const,
        position: { x: spec.x, y: spec.y },
        data: {
          title: spec.title,
          subtitle: spec.subtitle,
          glyph: spec.glyph,
          state: derived.states[spec.id]?.state ?? "idle",
          detail: derived.states[spec.id]?.detail,
        },
        draggable: false,
      })),
    [derived],
  );

  const edges: Edge[] = useMemo(
    () =>
      EDGE_SPECS.map((spec) => {
        const active = derived.activeEdges[spec.id];
        return {
          id: `${spec.id}-${replay}`,
          source: spec.source,
          target: spec.target,
          type: "particle",
          data: { active: Boolean(active), delay: active?.delay ?? 0, tone: active?.tone ?? spec.tone },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: TONE_HEX[spec.tone] ?? TONE_HEX.muted,
            width: 16,
            height: 16,
          },
        };
      }),
    [derived, replay],
  );

  return (
    <>
      <div className="pipeline-toolbar">
        <div>
          <p className="page-eyebrow">Live architecture</p>
          <h2 className="panel-title">Enforcement pipeline</h2>
          <p className="fine-print">
            The particle trail follows the final step of the recorded run. Nodes show every stage
            that actually produced an audit event; a denial stops before authorization and execution.
          </p>
        </div>
        <div className="pipeline-actions">
          <button type="button" className="btn btn--primary btn--sm" onClick={onRun} disabled={busy}>
            {busy ? "Running through gateway…" : "Run secret-read attack"}
          </button>
        </div>
      </div>

      {error ? <p className="field-error">{error}</p> : null}

      <div className="pipeline-canvas">
        <ReactFlow
          key={replay}
          nodes={nodes}
          edges={edges}
          nodeTypes={NODE_TYPES}
          edgeTypes={EDGE_TYPES}
          fitView
          fitViewOptions={{ padding: 0.18 }}
          minZoom={0.25}
          maxZoom={1.4}
          proOptions={{ hideAttribution: true }}
          nodesDraggable={false}
          nodesConnectable={false}
          elementsSelectable={false}
          className={run ? "" : "pipeline-canvas--idle"}
        >
          <Background color="#25344f" gap={26} size={1} />
          <Controls showInteractive={false} />
        </ReactFlow>
        {!run ? (
          <div className="pipeline-empty">
            <p className="empty-title">No simulation loaded</p>
            <p className="empty-message">
              Run the scenario to animate the real path. Every node state below comes from the
              recorded run, not from the animation.
            </p>
            <button type="button" className="btn btn--primary btn--sm" onClick={onRun} disabled={busy}>
              Run secret-read attack
            </button>
          </div>
        ) : null}
      </div>

      {run ? (
        <div className="pipeline-verdict">
          <div className="pipeline-verdict-main">
            <DecisionBadge decision={run.result.decision} />
            <span className="mono">{run.result.reason_code ?? "—"}</span>
            <Badge tone={run.result.side_effect ? "coral" : "teal"}>
              {run.result.side_effect ? "side effect" : "no side effect"}
            </Badge>
            <span className="muted mono">{run.run_id}</span>
          </div>
          <p className="detail-explanation">{run.result.explanation}</p>
          <div className="pipeline-grid">
            <div className="kv">
              <span className="kv-label">blocked at</span>
              <span className="kv-value mono">{run.result.blocked_at ?? "none"}</span>
            </div>
            <div className="kv">
              <span className="kv-label">executor</span>
              <span className="kv-value mono">
                {run.result.executed ? "ran the action" : "never reached"}
              </span>
            </div>
            <div className="kv">
              <span className="kv-label">mock outbox</span>
              <span className="kv-value mono">
                {run.result.outbox_before} → {run.result.outbox_after}
              </span>
            </div>
            <div className="kv">
              <span className="kv-label">execution rows</span>
              <span className="kv-value mono">{run.result.execution_rows}</span>
            </div>
            <div className="kv">
              <span className="kv-label">audit</span>
              <span className="kv-value mono">
                {run.audit.event_count} events · <Hash value={run.audit.head} />
              </span>
            </div>
            <div className="kv">
              <span className="kv-label">links</span>
              <span className="kv-value">
                <Link className="btn btn--ghost btn--xs" to={`/logs?request=${encodeURIComponent(run.result.request_id)}`}>
                  Audit events
                </Link>
              </span>
            </div>
          </div>

          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Step</th>
                  <th>Call</th>
                  <th>Decision</th>
                  <th>Status</th>
                  <th>Events</th>
                  <th>Observed</th>
                </tr>
              </thead>
              <tbody>
                {run.steps.map((step) => (
                  <tr key={step.step}>
                    <td className="mono">{step.step}</td>
                    <td className="mono">
                      {step.request.tool_name}.{step.request.operation}
                    </td>
                    <td>
                      <DecisionBadge decision={step.response.decision} />
                    </td>
                    <td className="mono">{step.response.status}</td>
                    <td className="mono">{step.audit_events.length}</td>
                    <td className="fine-print">
                      {Object.entries(step.observed)
                        .map(([key, value]) => `${key}=${String(value)}`)
                        .join(" · ")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <details className="detail-raw">
            <summary>Recorded audit events for the denied call</summary>
            <JsonBlock value={run.steps[run.steps.length - 1]?.audit_events ?? []} maxHeight={280} />
          </details>
        </div>
      ) : null}
    </>
  );
}
