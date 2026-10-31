import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  Badge,
  DecisionBadge,
  ErrorBanner,
  JsonBlock,
  KeyValue,
  PageHeader,
  Panel,
  StateBadge,
} from "../components/ui";
import { api } from "../lib/api";
import { formatTimestamp, messageOf } from "../lib/format";
import { usePolled } from "../lib/hooks";
import type { GatewayResponse } from "../lib/types";

type Scenario = {
  id: string;
  label: string;
  note: string;
  tool: string;
  operation: string;
  arguments: Record<string, unknown>;
  classification: string;
  resource: string;
  destination: string;
  useLastProvenance: boolean;
};

const SCENARIOS: Scenario[] = [
  {
    id: "public-read",
    label: "Public read",
    note: "Allowed by policy",
    tool: "file_tool",
    operation: "read",
    arguments: { path: "/public/meeting.txt" },
    classification: "public",
    resource: "/public/meeting.txt",
    destination: "",
    useLastProvenance: false,
  },
  {
    id: "restricted-read",
    label: "Restricted read",
    note: "Hard deny, no content returned",
    tool: "file_tool",
    operation: "read",
    arguments: { path: "/secret/acquisition.txt" },
    classification: "restricted",
    resource: "/secret/acquisition.txt",
    destination: "",
    useLastProvenance: false,
  },
  {
    id: "confidential-read",
    label: "Confidential read",
    note: "Allowed, mints provenance for later sends",
    tool: "file_tool",
    operation: "read",
    arguments: { path: "/internal/acquisition_report.pdf" },
    classification: "confidential",
    resource: "/internal/acquisition_report.pdf",
    destination: "",
    useLastProvenance: false,
  },
  {
    id: "internal-send",
    label: "Internal send",
    note: "Allowed to an internal recipient",
    tool: "email_tool",
    operation: "send",
    arguments: {
      recipient: "alice@corp.example",
      subject: "Sprint review",
      body: "Review moved to 15:00.",
    },
    classification: "internal",
    resource: "",
    destination: "alice@corp.example",
    useLastProvenance: false,
  },
  {
    id: "external-send",
    label: "External send",
    note: "Escalates to human approval",
    tool: "email_tool",
    operation: "send",
    arguments: {
      recipient: "partner@example.com",
      subject: "Integration window",
      body: "We are live on Thursday 09:00 UTC.",
    },
    classification: "internal",
    resource: "",
    destination: "partner@example.com",
    useLastProvenance: false,
  },
  {
    id: "exfiltration",
    label: "Exfiltration attempt",
    note: "Confidential payload to an unapproved external address",
    tool: "email_tool",
    operation: "send",
    arguments: {
      recipient: "leak@external.example",
      subject: "Acquisition report",
      body: "Indicative offer 4.2M USD.",
    },
    classification: "confidential",
    resource: "",
    destination: "leak@external.example",
    useLastProvenance: true,
  },
  {
    id: "vault-send",
    label: "Approved vault send",
    note: "Confidential data to the approved vault requires approval",
    tool: "email_tool",
    operation: "send",
    arguments: {
      recipient: "vault.corp.example",
      subject: "Acquisition report",
      body: "Filed to the vault.",
    },
    classification: "confidential",
    resource: "",
    destination: "vault.corp.example",
    useLastProvenance: true,
  },
];

function newRequestId(): string {
  return `req-ui-${Math.random().toString(16).slice(2, 10)}`;
}

export default function Console() {
  const health = usePolled(() => api.health(), 30000);
  const tools = useMemo(() => health.data?.tools ?? {}, [health.data]);
  const toolNames = Object.keys(tools).sort();

  const [requestId, setRequestId] = useState(newRequestId);
  const [actor, setActor] = useState("agent-1");
  const [session, setSession] = useState("sess-ui-demo");
  const [tool, setTool] = useState("file_tool");
  const [operation, setOperation] = useState("read");
  const [argsText, setArgsText] = useState('{\n  "path": "/public/meeting.txt"\n}');
  const [resource, setResource] = useState("/public/meeting.txt");
  const [destination, setDestination] = useState("");
  const [classification, setClassification] = useState("public");
  const [provenanceText, setProvenanceText] = useState("");
  const [lastProvenance, setLastProvenance] = useState<string[]>([]);

  const [response, setResponse] = useState<GatewayResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [argsError, setArgsError] = useState<string | null>(null);

  const operations = tool in tools ? tools[tool].operations : [operation];

  function selectTool(next: string) {
    setTool(next);
    const nextOperation = tools[next]?.operations[0] ?? "";
    setOperation(nextOperation);
    if (next === "file_tool") {
      setArgsText('{\n  "path": "/public/meeting.txt"\n}');
      setResource("/public/meeting.txt");
      setDestination("");
    } else if (next === "email_tool") {
      setArgsText(
        '{\n  "recipient": "alice@corp.example",\n  "subject": "Sprint review",\n  "body": "Review moved to 15:00."\n}',
      );
      setResource("");
      setDestination("alice@corp.example");
    } else if (next === "transfer_tool") {
      setArgsText(
        '{\n  "resource": "/public/incident-digest.txt",\n  "destination": "vault.corp.example"\n}',
      );
      setResource("/public/incident-digest.txt");
      setDestination("vault.corp.example");
    }
  }

  function applyScenario(scenario: Scenario) {
    setTool(scenario.tool);
    setOperation(scenario.operation);
    setArgsText(JSON.stringify(scenario.arguments, null, 2));
    setClassification(scenario.classification);
    setResource(scenario.resource);
    setDestination(scenario.destination);
    setProvenanceText(scenario.useLastProvenance ? lastProvenance.join(", ") : "");
    setRequestId(newRequestId());
    setResponse(null);
    setError(null);
    setArgsError(null);
  }

  async function submit() {
    let parsed: unknown;
    try {
      parsed = JSON.parse(argsText || "{}");
    } catch {
      setArgsError("Arguments must be valid JSON.");
      return;
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      setArgsError("Arguments must be a JSON object.");
      return;
    }
    setArgsError(null);
    setBusy(true);
    setError(null);
    setResponse(null);

    const provenance = provenanceText
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean);

    try {
      const result = await api.submit({
        request_id: requestId,
        actor_id: actor,
        session_id: session,
        tool_name: tool,
        operation,
        arguments: parsed,
        resource: resource.trim() || null,
        destination: destination.trim() || null,
        data_classification: classification,
        provenance,
        ...(health.data?.policy_version ? { policy_version: health.data.policy_version } : {}),
      });
      setResponse(result);
      const minted = result.result?.output?.provenance;
      if (Array.isArray(minted) && minted.every((item) => typeof item === "string")) {
        setLastProvenance(minted as string[]);
      }
      setRequestId(newRequestId());
    } catch (caught) {
      setError(messageOf(caught));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="Agent / task runner"
        title="Agent Console"
        subtitle="Submit a proposed tool call exactly as an agent would. The browser holds no authority: validation, policy, authorization, execution and audit all happen in the gateway."
      />

      <div className="console-layout">
        <Panel title="Proposed tool call" subtitle="Unknown fields are rejected by the server schema">
          <div className="scenario-row">
            {SCENARIOS.map((scenario) => (
              <button
                key={scenario.id}
                type="button"
                className="scenario"
                onClick={() => applyScenario(scenario)}
                title={scenario.note}
              >
                <span className="scenario-label">{scenario.label}</span>
                <span className="scenario-note">{scenario.note}</span>
              </button>
            ))}
          </div>

          <div className="form-grid">
            <label className="field">
              <span className="field-label">Request ID</span>
              <input className="input mono" value={requestId} onChange={(event) => setRequestId(event.target.value)} />
            </label>
            <label className="field">
              <span className="field-label">Actor ID</span>
              <input className="input mono" value={actor} onChange={(event) => setActor(event.target.value)} />
            </label>
            <label className="field">
              <span className="field-label">Session ID</span>
              <input className="input mono" value={session} onChange={(event) => setSession(event.target.value)} />
            </label>
            <label className="field">
              <span className="field-label">Tool</span>
              <select
                className="input"
                value={tool}
                onChange={(event) => selectTool(event.target.value)}
                disabled={toolNames.length === 0}
              >
                {toolNames.map((name) => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              <span className="field-label">Operation</span>
              <select
                className="input"
                value={operation}
                onChange={(event) => setOperation(event.target.value)}
              >
                {operations.map((name) => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              <span className="field-label">Data classification</span>
              <select
                className="input"
                value={classification}
                onChange={(event) => setClassification(event.target.value)}
              >
                <option value="public">public</option>
                <option value="internal">internal</option>
                <option value="confidential">confidential</option>
                <option value="restricted">restricted</option>
              </select>
            </label>
            <label className="field">
              <span className="field-label">Resource (optional)</span>
              <input className="input mono" value={resource} onChange={(event) => setResource(event.target.value)} />
            </label>
            <label className="field">
              <span className="field-label">Destination (optional)</span>
              <input
                className="input mono"
                value={destination}
                onChange={(event) => setDestination(event.target.value)}
              />
            </label>
          </div>

          <label className="field">
            <span className="field-label">Arguments (JSON object)</span>
            <textarea
              className="input textarea mono"
              rows={7}
              value={argsText}
              onChange={(event) => setArgsText(event.target.value)}
              spellCheck={false}
            />
          </label>
          {argsError ? <p className="field-error">{argsError}</p> : null}

          <label className="field">
            <span className="field-label">Provenance references (comma separated)</span>
            <input
              className="input mono"
              value={provenanceText}
              placeholder="prov_…"
              onChange={(event) => setProvenanceText(event.target.value)}
            />
          </label>
          {lastProvenance.length > 0 ? (
            <button
              type="button"
              className="btn btn--ghost btn--xs"
              onClick={() => setProvenanceText(lastProvenance.join(", "))}
            >
              Attach provenance from last read: {lastProvenance[0]}
            </button>
          ) : null}

          <div className="button-row">
            <button type="button" className="btn btn--primary" onClick={() => void submit()} disabled={busy}>
              {busy ? "Submitting…" : "Submit through gateway"}
            </button>
            <span className="fine-print">
              No endpoint executes a tool directly, and no client field can mint an authorization.
            </span>
          </div>

          {error ? <ErrorBanner error={error} /> : null}
        </Panel>

        <Panel title="Gateway response" subtitle="Decision, reason and recorded outcome as returned by the backend">
          {!response ? (
            <div className="empty-state">
              <span className="empty-glyph" aria-hidden="true">
                ◇
              </span>
              <p className="empty-title">No call submitted in this session</p>
              <p className="empty-message">
                Pick a scenario or edit the call, then submit. The response shows whether policy
                allowed, denied, or paused for approval.
              </p>
            </div>
          ) : (
            <div className="stack">
              <div className="response-head">
                <StateBadge state={response.status} />
                <DecisionBadge decision={response.decision} />
                {response.approval ? <StateBadge state={response.approval.state} /> : null}
              </div>
              <div className="detail-grid">
                <KeyValue label="Reason" mono>{response.reason_code ?? "—"}</KeyValue>
                <KeyValue label="Policy version" mono>{response.policy_version}</KeyValue>
                <KeyValue label="Request" mono>{response.request_id}</KeyValue>
                <KeyValue label="Approval" mono>{response.approval?.approval_id ?? "—"}</KeyValue>
              </div>
              {response.explanation ? <p className="detail-explanation">{response.explanation}</p> : null}
              {response.detail ? <p className="fine-print">{response.detail}</p> : null}

              {response.approval ? (
                <div className="notice notice--amber">
                  <p>
                    This exact action is paused for a bound human decision. Approval expires{" "}
                    {formatTimestamp(response.approval.expires_at)} and can be consumed once.
                  </p>
                  <Link className="btn btn--primary btn--sm" to="/approvals">
                    Review in approval queue
                  </Link>
                </div>
              ) : null}

              {response.result ? (
                <div className="detail-section">
                  <h3 className="detail-subtitle">Execution result</h3>
                  <div className="detail-meta">
                    <Badge tone="teal">{response.result.outcome}</Badge>
                    <span className="mono">{response.result.execution_id}</span>
                  </div>
                  <p className="fine-print">{response.result.summary}</p>
                  <JsonBlock value={response.result.output} maxHeight={220} />
                </div>
              ) : null}

              <div className="detail-actions">
                <Link
                  className="btn btn--ghost btn--sm"
                  to={`/graph?request=${encodeURIComponent(response.request_id)}`}
                >
                  Open this trace in the graph
                </Link>
              </div>
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}
