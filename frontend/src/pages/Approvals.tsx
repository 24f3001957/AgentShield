import { useMemo, useState } from "react";
import {
  Badge,
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
import { api, requestFromApproval } from "../lib/api";
import {
  formatTimestamp,
  messageOf,
  pluralize,
  relativeTime,
  untilTime,
} from "../lib/format";
import { useNow, usePolled } from "../lib/hooks";
import type { Approval, GatewayResponse } from "../lib/types";

const FILTERS = [
  { value: "PENDING_APPROVAL", label: "Pending" },
  { value: "all", label: "All" },
  { value: "APPROVED", label: "Approved" },
  { value: "REJECTED", label: "Rejected" },
  { value: "EXPIRED", label: "Expired" },
];

export default function Approvals() {
  const now = useNow(5000);
  const [filter, setFilter] = useState("PENDING_APPROVAL");
  const [approver, setApprover] = useState("sec-lead");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [execution, setExecution] = useState<GatewayResponse | null>(null);

  const approvals = usePolled(() => api.approvals(), 4000);
  const list = approvals.data?.approvals ?? [];

  const filtered = useMemo(
    () => (filter === "all" ? list : list.filter((item) => item.state === filter)),
    [list, filter],
  );
  const selected = list.find((item) => item.approval_id === selectedId) ?? filtered[0] ?? null;
  const pendingCount = list.filter((item) => item.state === "PENDING_APPROVAL").length;

  async function decide(item: Approval, decision: "APPROVE" | "REJECT") {
    if (!approver.trim()) {
      setActionError("An approver name is required (simulated identity in this prototype).");
      return;
    }
    setBusy(decision);
    setActionError(null);
    setNote(null);
    setExecution(null);
    try {
      const result = await api.decide(item.approval_id, approver.trim(), decision);
      setNote(
        `${decision === "APPROVE" ? "Approved" : "Rejected"} by ${result.approval.approver}. ` +
          "The backend recorded the decision; no tool ran.",
      );
      // Keep the decided action in view (it may leave a pending-only filter).
      setSelectedId(item.approval_id);
      setFilter("all");
      await approvals.refresh();
    } catch (error) {
      setActionError(messageOf(error));
    } finally {
      setBusy(null);
    }
  }

  async function execute(item: Approval) {
    setBusy("EXECUTE");
    setActionError(null);
    setExecution(null);
    try {
      const response = await api.execute(
        item.request_id,
        item.approval_id,
        requestFromApproval(item),
      );
      setExecution(response);
      await approvals.refresh();
    } catch (error) {
      setActionError(messageOf(error));
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="Human checkpoint"
        title="Approvals"
        subtitle="Approval binds to the canonical SHA-256 fingerprint of the exact action, one-time, with an expiry. Approving never executes; execution is a separate server-checked step."
        actions={
          <div className="header-meta">
            <RefreshNote updatedAt={approvals.updatedAt} />
            <Badge tone={pendingCount ? "amber" : "muted"}>
              {pluralize(pendingCount, "pending request")}
            </Badge>
          </div>
        }
      />

      {approvals.error ? (
        <ErrorBanner error={approvals.error} onRetry={() => void approvals.refresh()} />
      ) : null}

      <div className="tabs" role="tablist" aria-label="Approval state filter">
        {FILTERS.map((tab) => (
          <button
            key={tab.value}
            type="button"
            role="tab"
            aria-selected={filter === tab.value}
            className={`tab${filter === tab.value ? " tab--active" : ""}`}
            onClick={() => setFilter(tab.value)}
          >
            {tab.label}
            <span className="tab-count">
              {tab.value === "all"
                ? list.length
                : list.filter((item) => item.state === tab.value).length}
            </span>
          </button>
        ))}
      </div>

      <div className="approval-layout">
        <Panel
          title="Queue"
          subtitle={`${pluralize(filtered.length, "approval")} in this view`}
          padded={false}
        >
          {approvals.loading && !approvals.data ? (
            <div className="pad">
              <Loading label="Loading approvals" />
            </div>
          ) : filtered.length === 0 ? (
            <div className="pad">
              <EmptyState
                title="No approvals in this state"
                message="External sends and confidential transfers to approved destinations appear here after a policy decision of APPROVAL."
              />
            </div>
          ) : (
            <ul className="approval-list">
              {filtered.map((item) => (
                <li key={item.approval_id}>
                  <button
                    type="button"
                    className={`approval-item${selected?.approval_id === item.approval_id ? " approval-item--active" : ""}`}
                    onClick={() => {
                      setSelectedId(item.approval_id);
                      setNote(null);
                      setExecution(null);
                      setActionError(null);
                    }}
                  >
                    <div className="approval-item-top">
                      <span className="mono approval-tool">
                        {item.binding.tool_name}.{item.binding.operation}
                      </span>
                      <StateBadge state={item.state} />
                    </div>
                    <p className="approval-target mono">
                      {item.binding.destination ??
                        item.binding.resource ??
                        String(item.binding.arguments.path ?? "—")}
                    </p>
                    <div className="approval-item-meta">
                      <span className="muted">{item.binding.actor_id}</span>
                      <span className="muted">{relativeTime(item.created_at, now)}</span>
                      <Badge tone="muted">{item.binding.data_classification}</Badge>
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="Exact-call review" subtitle="What the approver is authorizing, byte for byte">
          {!selected ? (
            <EmptyState title="Select an approval" message="The bound action and its evidence appear here." />
          ) : (
            <div className="stack">
              <div className="detail-meta">
                <StateBadge state={selected.state} />
                <span className="mono">{selected.approval_id}</span>
                <span className="muted">
                  {selected.state === "PENDING_APPROVAL"
                    ? untilTime(selected.expires_at, now)
                    : `created ${formatTimestamp(selected.created_at)}`}
                </span>
              </div>

              <div className="detail-grid">
                <KeyValue label="Actor" mono>{selected.binding.actor_id}</KeyValue>
                <KeyValue label="Session" mono>{selected.binding.session_id}</KeyValue>
                <KeyValue label="Tool" mono>{selected.binding.tool_name}</KeyValue>
                <KeyValue label="Operation" mono>{selected.binding.operation}</KeyValue>
                <KeyValue label="Destination" mono>{selected.binding.destination ?? "—"}</KeyValue>
                <KeyValue label="Resource" mono>{selected.binding.resource ?? "—"}</KeyValue>
                <KeyValue label="Data class" mono>{selected.binding.data_classification}</KeyValue>
                <KeyValue label="Policy version" mono>{selected.binding.policy_version}</KeyValue>
                <KeyValue label="Request" mono>{selected.request_id}</KeyValue>
                <KeyValue label="Expires" mono>{formatTimestamp(selected.expires_at)}</KeyValue>
              </div>

              <div className="kv">
                <span className="kv-label">action fingerprint</span>
                <Hash value={selected.fingerprint} />
              </div>

              <div className="detail-section">
                <h3 className="detail-subtitle">Bound arguments</h3>
                <JsonBlock value={selected.binding.arguments} maxHeight={200} />
              </div>

              {selected.binding.provenance.length > 0 ? (
                <div className="detail-section">
                  <h3 className="detail-subtitle">Provenance</h3>
                  <JsonBlock value={selected.binding.provenance} maxHeight={110} />
                </div>
              ) : null}

              {selected.state === "PENDING_APPROVAL" ? (
                <div className="approval-actions">
                  <label className="field">
                    <span className="field-label">Approver (simulated identity)</span>
                    <input
                      className="input"
                      value={approver}
                      maxLength={128}
                      onChange={(event) => setApprover(event.target.value)}
                    />
                  </label>
                  <div className="button-row">
                    <button
                      type="button"
                      className="btn btn--primary"
                      disabled={busy !== null}
                      onClick={() => void decide(selected, "APPROVE")}
                    >
                      {busy === "APPROVE" ? "Submitting…" : "Approve exact action"}
                    </button>
                    <button
                      type="button"
                      className="btn btn--danger"
                      disabled={busy !== null}
                      onClick={() => void decide(selected, "REJECT")}
                    >
                      {busy === "REJECT" ? "Submitting…" : "Reject"}
                    </button>
                  </div>
                  <p className="fine-print">
                    The UI waits for the backend response. Mutation, expiry, replay and hard-denied
                    actions are rejected server-side, not hidden here.
                  </p>
                </div>
              ) : null}

              {selected.state === "APPROVED" ? (
                <div className="approval-actions">
                  <div className="notice notice--amber">
                    Approved by {selected.approver ?? "—"} at {formatTimestamp(selected.decided_at)}.
                    Nothing has executed yet.
                  </div>
                  <button
                    type="button"
                    className="btn btn--primary"
                    disabled={busy !== null}
                    onClick={() => void execute(selected)}
                  >
                    {busy === "EXECUTE" ? "Submitting…" : "Execute revalidated action"}
                  </button>
                  <p className="fine-print">
                    This re-submits the exact bound request. The gateway re-evaluates policy,
                    re-checks the fingerprint and consumes the approval once before the executor runs.
                  </p>
                </div>
              ) : null}

              {note ? <div className="notice notice--teal">{note}</div> : null}
              {actionError ? <ErrorBanner error={actionError} /> : null}

              {execution ? (
                <div className="notice notice--panel">
                  <div className="detail-meta">
                    <StateBadge state={execution.status} />
                    <DecisionBadge decision={execution.decision} />
                    <span className="mono">{execution.reason_code}</span>
                  </div>
                  <p>{execution.detail ?? execution.explanation}</p>
                  {execution.result ? (
                    <p className="fine-print">
                      Execution {execution.result.outcome}: {execution.result.summary}
                    </p>
                  ) : null}
                </div>
              ) : null}

              <div className="detail-section">
                <h3 className="detail-subtitle">Lifecycle</h3>
                <div className="kv">
                  <span className="kv-label">requested</span>
                  <span>{formatTimestamp(selected.created_at)}</span>
                </div>
                <div className="kv">
                  <span className="kv-label">decided</span>
                  <span>{formatTimestamp(selected.decided_at)}</span>
                </div>
                <div className="kv">
                  <span className="kv-label">consumed</span>
                  <span>{formatTimestamp(selected.consumed_at)}</span>
                </div>
                <div className="kv">
                  <span className="kv-label">executed</span>
                  <span>{formatTimestamp(selected.executed_at)}</span>
                </div>
              </div>
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}
