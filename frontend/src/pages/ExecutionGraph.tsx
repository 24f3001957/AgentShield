import {
  Background,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  Badge,
  CopyButton,
  DecisionBadge,
  EmptyState,
  ErrorBanner,
  Hash,
  JsonBlock,
  KeyValue,
  Loading,
  PageHeader,
  Panel,
  RefreshNote,
  StateBadge,
} from "../components/ui";
import { api } from "../lib/api";
import { metaFor, type Tone } from "../lib/events";
import { downloadJson, formatClock, formatTimestamp, messageOf, pluralize } from "../lib/format";
import { usePolled } from "../lib/hooks";
import { groupChains, type Chain } from "../lib/trace";
import type { AuditEvent, ToolCallDetail } from "../lib/types";

type GraphNodeData = {
  label: string;
  tone: Tone;
  glyph: string;
  seq: number | null;
  primary: string;
  secondary: string;
  time: string;
  dimmed: boolean;
  session?: boolean;
};

type GraphNode = Node<GraphNodeData, "event">;

const TONE_HEX: Record<Tone, string> = {
  teal: "#55d6be",
  blue: "#79afff",
  amber: "#f5be67",
  coral: "#ff8585",
  purple: "#d0a7ff",
  muted: "#46587a",
};

function EventNode({ data, selected }: NodeProps<GraphNode>) {
  return (
    <div
      className={[
        "graph-node",
        `graph-node--${data.tone}`,
        data.session ? "graph-node--session" : "",
        selected ? "graph-node--selected" : "",
        data.dimmed ? "graph-node--dimmed" : "",
      ]
        .filter(Boolean)
        .join(" ")}
    >
      <Handle type="target" position={Position.Left} className="graph-handle" />
      <div className="graph-node-head">
        <span className="graph-glyph" aria-hidden="true">
          {data.glyph}
        </span>
        <span className="graph-label">{data.label}</span>
        {data.seq !== null ? <span className="graph-seq mono">#{data.seq}</span> : null}
      </div>
      <div className="graph-node-primary mono">{data.primary}</div>
      {data.secondary ? <div className="graph-node-secondary">{data.secondary}</div> : null}
      <div className="graph-node-foot mono">{data.time}</div>
      <Handle type="source" position={Position.Right} className="graph-handle" />
    </div>
  );
}

const nodeTypes = { event: EventNode };

function summarize(event: AuditEvent): { primary: string; secondary: string } {
  const payload = event.payload;
  const tool = String(payload.tool_name ?? "");
  const operation = String(payload.operation ?? "");
  switch (event.event_type) {
    case "tool_call_received":
      return {
        primary: `${tool}.${operation}`,
        secondary: String(payload.actor_id ?? ""),
      };
    case "policy_decision":
      return {
        primary: String(payload.reason_code ?? payload.decision ?? ""),
        secondary: `${String(payload.decision ?? "")} · rule ${String(payload.rule_name ?? "—")}`,
      };
    case "approval_created":
    case "approval_decided":
    case "approval_consumed":
    case "approval_revalidated":
    case "approval_rejected":
      return {
        primary: String(payload.approval_id ?? payload.reason_code ?? "approval"),
        secondary: String(payload.decision ?? payload.state ?? ""),
      };
    case "authorization_issued":
      return {
        primary: String(payload.kind ?? "authorization"),
        secondary: `expires ${formatClock(Number(payload.expires_at) * 1000)}`,
      };
    case "provenance_recorded":
      return {
        primary: String(payload.source_path ?? ""),
        secondary: `${String(payload.classification ?? "")} · ${String(payload.prov_id ?? "")}`,
      };
    case "execution_completed":
    case "execution_recorded":
    case "execution_failed":
      return {
        primary: String(payload.outcome ?? event.event_type),
        secondary: String(payload.summary ?? payload.error ?? ""),
      };
    case "audit_verification":
      return {
        primary: `${String(payload.event_count ?? "")} events`,
        secondary: payload.valid ? "valid" : "failures recorded",
      };
    default:
      return {
        primary: String(payload.reason_code ?? payload.request_id ?? ""),
        secondary: String(payload.detail ?? ""),
      };
  }
}

function buildGraph(
  chains: Chain[],
  matched: Set<number>,
  dimAll: boolean,
): { nodes: GraphNode[]; edges: Edge[] } {
  const nodes: GraphNode[] = [];
  const edges: Edge[] = [];
  const sessionNodes = new Map<string, string>();
  let row = 0;

  for (const chain of chains) {
    const y = row * 170;
    let x = 40;

    if (!chain.requestId) {
      // system events (integrity checks)
    } else if (!sessionNodes.has(chain.session)) {
      const sessionNodeId = `session:${chain.session}`;
      sessionNodes.set(chain.session, sessionNodeId);
      nodes.push({
        id: sessionNodeId,
        type: "event",
        position: { x: 0, y: y + 14 },
        data: {
          label: "Agent / session",
          tone: "blue",
          glyph: "◈",
          seq: null,
          primary: chain.session,
          secondary: "recorded session",
          time: formatClock(chain.events[0]?.timestamp),
          dimmed: false,
          session: true,
        },
      });
      x = 290;
    } else {
      x = 290;
    }

    chain.events.forEach((event, index) => {
      const meta = metaFor(event);
      const summary = summarize(event);
      const nodeId = `e${event.seq}`;
      nodes.push({
        id: nodeId,
        type: "event",
        position: { x: x + index * 260, y },
        data: {
          label: meta.label,
          tone: meta.tone,
          glyph: meta.glyph,
          seq: event.seq,
          primary: summary.primary,
          secondary: summary.secondary,
          time: formatClock(event.timestamp),
          dimmed: dimAll || !matched.has(event.seq),
        },
      });

      if (index > 0) {
        const previous = chain.events[index - 1];
        edges.push(makeEdge(`e${previous.seq}`, nodeId, meta.tone, meta.tone === "teal"));
      } else if (chain.requestId) {
        const sessionNodeId = sessionNodes.get(chain.session);
        if (sessionNodeId) {
          edges.push(makeEdge(sessionNodeId, nodeId, "blue", false, true));
        }
      }
    });

    row += 1;
  }

  return { nodes, edges };
}

function makeEdge(
  source: string,
  target: string,
  tone: Tone,
  animated: boolean,
  dashed = false,
): Edge {
  const color = TONE_HEX[tone];
  return {
    id: `${source}->${target}`,
    source,
    target,
    type: "smoothstep",
    animated,
    style: {
      stroke: color,
      strokeWidth: 1.4,
      strokeDasharray: dashed ? "5 5" : undefined,
      opacity: dashed ? 0.6 : 0.85,
    },
    markerEnd: { type: MarkerType.ArrowClosed, color, width: 18, height: 18 },
  };
}

export default function ExecutionGraph() {
  const [searchParams] = useSearchParams();
  const initialRequest = searchParams.get("request");
  const initialSession = searchParams.get("session");
  const initialFocus = searchParams.get("focus");

  const [liveFollow, setLiveFollow] = useState(true);
  const events = usePolled(() => api.auditEvents(800), liveFollow ? 5000 : 0);
  const [query, setQuery] = useState("");
  const [session, setSession] = useState(initialSession ?? "all");
  const [decision, setDecision] = useState("all");
  const [selected, setSelected] = useState<number | null>(
    initialFocus ? Number(initialFocus) : null,
  );
  const [detail, setDetail] = useState<ToolCallDetail | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);

  const auditEvents = events.data?.events ?? [];
  const { chains, sessions } = useMemo(() => groupChains(auditEvents), [auditEvents]);

  // Deep link from the dashboard/logs: focus the requested chain.
  useEffect(() => {
    if (!initialRequest || selected !== null) return;
    const chain = chains.find((item) => item.requestId === initialRequest);
    if (chain && chain.events.length > 0) setSelected(chain.events[0].seq);
  }, [chains, initialRequest, selected]);

  const matched = useMemo(() => {
    const set = new Set<number>();
    for (const event of auditEvents) {
      if (decision !== "all") {
        if (event.event_type !== "policy_decision" || event.payload.decision !== decision) {
          continue;
        }
      }
      if (query.trim()) {
        const needle = query.trim().toLowerCase();
        const haystack = [
          event.event_type,
          String(event.seq),
          event.event_hash,
          JSON.stringify(event.payload),
        ]
          .join(" ")
          .toLowerCase();
        if (!haystack.includes(needle)) continue;
      }
      set.add(event.seq);
    }
    return set;
  }, [auditEvents, decision, query]);

  const filterActive = query.trim() !== "" || decision !== "all";

  const visibleChains = useMemo(
    () =>
      chains.filter((chain) => {
        if (session !== "all" && chain.session !== session) return false;
        return chain.events.some((event) => matched.has(event.seq));
      }),
    [chains, session, matched],
  );

  const { nodes, edges } = useMemo(
    () => buildGraph(visibleChains, matched, filterActive),
    [visibleChains, matched, filterActive],
  );

  const selectedEvent = useMemo(
    () => auditEvents.find((event) => event.seq === selected) ?? null,
    [auditEvents, selected],
  );

  const selectedRequestId =
    selectedEvent && typeof selectedEvent.payload.request_id === "string"
      ? selectedEvent.payload.request_id
      : null;

  useEffect(() => {
    if (!selectedRequestId) {
      setDetail(null);
      setDetailError(null);
      return;
    }
    let alive = true;
    setDetailError(null);
    api
      .toolCall(selectedRequestId)
      .then((data) => {
        if (alive) setDetail(data);
      })
      .catch((error: unknown) => {
        if (!alive) return;
        setDetail(null);
        setDetailError(messageOf(error));
      });
    return () => {
      alive = false;
    };
  }, [selectedRequestId]);

  const payload = selectedEvent?.payload ?? {};

  return (
    <>
      <PageHeader
        eyebrow="Forensic reconstruction"
        title="Execution Graph"
        subtitle="Nodes are recorded audit events; edges are their recorded sequence. The graph never infers execution from agent intent."
        actions={
          <div className="header-meta">
            <RefreshNote updatedAt={events.updatedAt} />
            <button
              type="button"
              className="btn btn--ghost btn--sm"
              onClick={() => downloadJson(`agentshield-trace-${Date.now()}.json`, visibleChains)}
              disabled={visibleChains.length === 0}
            >
              Export trace JSON
            </button>
          </div>
        }
      />

      {events.error ? <ErrorBanner error={events.error} onRetry={() => void events.refresh()} /> : null}

      <div className="graph-toolbar">
        <input
          className="input input--search"
          type="search"
          placeholder="Search event, request, tool, hash…"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          aria-label="Search the execution graph"
        />
        <label className="select-field">
          <span className="select-label">Session</span>
          <select value={session} onChange={(event) => setSession(event.target.value)}>
            <option value="all">All sessions</option>
            {sessions.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
        </label>
        <label className="select-field">
          <span className="select-label">Decision</span>
          <select value={decision} onChange={(event) => setDecision(event.target.value)}>
            <option value="all">All decisions</option>
            <option value="ALLOW">ALLOW</option>
            <option value="APPROVAL">APPROVAL</option>
            <option value="DENY">DENY</option>
          </select>
        </label>
        <button
          type="button"
          className={`btn btn--sm ${liveFollow ? "btn--primary" : "btn--ghost"}`}
          onClick={() => setLiveFollow((value) => !value)}
          aria-pressed={liveFollow}
        >
          {liveFollow ? "Live follow on" : "Live follow off"}
        </button>
        <button type="button" className="btn btn--ghost btn--sm" onClick={() => void events.refresh()}>
          Refresh
        </button>
        <span className="graph-count">
          {pluralize(visibleChains.length, "trace")} · {pluralize(nodes.length, "node")}
        </span>
      </div>

      <div className="graph-legend">
        <span className="legend-item"><i className="dot dot--teal" /> allowed</span>
        <span className="legend-item"><i className="dot dot--coral" /> blocked / failed</span>
        <span className="legend-item"><i className="dot dot--amber" /> approval</span>
        <span className="legend-item"><i className="dot dot--purple" /> integrity</span>
        <span className="legend-item legend-muted">dimmed = filtered out</span>
      </div>

      <div className="graph-layout">
        <div className="graph-canvas">
          {events.loading && !events.data ? (
            <div className="pad">
              <Loading label="Loading audit events" />
            </div>
          ) : visibleChains.length === 0 ? (
            <div className="pad">
              <EmptyState
                title="No recorded events match"
                message="The graph only shows evidence that exists. Submit a tool call or clear the filters."
              />
            </div>
          ) : (
            <ReactFlow
              nodes={nodes}
              edges={edges}
              nodeTypes={nodeTypes}
              onNodeClick={(_, node) => {
                if (typeof node.data.seq === "number") setSelected(node.data.seq);
              }}
              fitView
              minZoom={0.2}
              maxZoom={1.6}
              proOptions={{ hideAttribution: true }}
              nodesDraggable={false}
              nodesConnectable={false}
              elementsSelectable
            >
              <Background color="#25344f" gap={26} size={1} />
              <MiniMap
                pannable
                zoomable
                className="graph-minimap"
                nodeColor={(node) => TONE_HEX[(node.data?.tone as Tone) ?? "muted"]}
                maskColor="rgba(8, 12, 24, 0.7)"
              />
              <Controls showInteractive={false} />
            </ReactFlow>
          )}
        </div>

        <aside className="graph-detail" aria-label="Event details">
          {!selectedEvent ? (
            <div className="detail-empty">
              <p className="empty-title">Select an event</p>
              <p className="empty-message">
                Hovering is not implemented as a hover-only affordance: click any node to pin its
                full evidence here.
              </p>
            </div>
          ) : (
            <div className="detail-body">
              <div className="detail-head">
                <div>
                  <p className="page-eyebrow">Event #{selectedEvent.seq}</p>
                  <h2 className="detail-title">{metaFor(selectedEvent).label}</h2>
                </div>
                <button
                  type="button"
                  className="btn btn--ghost btn--xs"
                  onClick={() => setSelected(null)}
                >
                  Close
                </button>
              </div>

              <div className="detail-meta">
                <span className="mono">{formatTimestamp(selectedEvent.timestamp)}</span>
                <CopyButton value={String(selectedEvent.seq)} label="Copy seq" />
              </div>

              <div className="detail-grid">
                <KeyValue label="Event type" mono>{selectedEvent.event_type}</KeyValue>
                <KeyValue label="Request" mono>{String(payload.request_id ?? "—")}</KeyValue>
                <KeyValue label="Session" mono>
                  {String(payload.session_id ?? selectedRequestId ?? "—")}
                </KeyValue>
                <KeyValue label="Tool" mono>{String(payload.tool_name ?? "—")}</KeyValue>
                <KeyValue label="Operation" mono>{String(payload.operation ?? "—")}</KeyValue>
                <KeyValue label="Decision">
                  {payload.decision ? (
                    <DecisionBadge decision={String(payload.decision) as never} />
                  ) : (
                    <span className="muted">—</span>
                  )}
                </KeyValue>
                <KeyValue label="Reason" mono>{String(payload.reason_code ?? "—")}</KeyValue>
                <KeyValue label="Rule" mono>{String(payload.rule_name ?? "—")}</KeyValue>
                <KeyValue label="Policy version" mono>
                  {String(payload.policy_version ?? "—")}
                </KeyValue>
                <KeyValue label="Classification" mono>
                  {String(payload.effective_classification ?? payload.data_classification ?? "—")}
                </KeyValue>
                <KeyValue label="Destination" mono>{String(payload.destination ?? "—")}</KeyValue>
                <KeyValue label="Resource" mono>{String(payload.resource ?? "—")}</KeyValue>
              </div>

              {payload.explanation ? (
                <p className="detail-explanation">{String(payload.explanation)}</p>
              ) : null}

              {Array.isArray(payload.provenance) && payload.provenance.length > 0 ? (
                <div className="detail-section">
                  <h3 className="detail-subtitle">Provenance</h3>
                  <JsonBlock value={payload.provenance} maxHeight={140} />
                </div>
              ) : null}

              <div className="detail-section">
                <h3 className="detail-subtitle">Integrity metadata</h3>
                <div className="kv">
                  <span className="kv-label">event hash</span>
                  <Hash value={selectedEvent.event_hash} />
                </div>
                <div className="kv">
                  <span className="kv-label">previous hash</span>
                  <Hash value={selectedEvent.prev_hash} />
                </div>
              </div>

              <div className="detail-section">
                <h3 className="detail-subtitle">Recorded request state</h3>
                {detailError ? (
                  <p className="fine-print">Not available for this request: {detailError}</p>
                ) : !selectedRequestId ? (
                  <p className="fine-print">This event is not bound to a tool-call request.</p>
                ) : !detail ? (
                  <Loading label="Loading request" />
                ) : (
                  <div className="stack-tight">
                    <div className="detail-meta">
                      <StateBadge state={detail.state} />
                      {detail.approval ? <StateBadge state={detail.approval.state} /> : null}
                    </div>
                    {detail.execution ? (
                      <p className="fine-print">
                        Execution {detail.execution.outcome}: {detail.execution.summary}
                      </p>
                    ) : (
                      <p className="fine-print">No execution ledger row for this request.</p>
                    )}
                    {detail.detail ? <p className="fine-print">{detail.detail}</p> : null}
                  </div>
                )}
              </div>

              <details className="detail-raw">
                <summary>Raw event payload</summary>
                <pre className="json-block">{JSON.stringify(selectedEvent, null, 2)}</pre>
              </details>
            </div>
          )}
        </aside>
      </div>

      <Panel title="How to read this graph" subtitle="Evidence rules the console follows" className="mt">
        <ul className="rules-list">
          <li>
            A <Badge tone="teal">DENY</Badge> branch stops at the policy decision node; there is no
            downstream execution edge unless a separate execution event exists.
          </li>
          <li>
            A <Badge tone="amber">PENDING</Badge> approval pauses the chain. Approval alone never
            renders as execution success — the execution event must be recorded.
          </li>
          <li>
            Edges are recorded sequence within a request; the session node only links requests that
            the audit record attributed to that session.
          </li>
        </ul>
      </Panel>
    </>
  );
}
