import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
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
} from "../components/ui";
import { api } from "../lib/api";
import { metaFor } from "../lib/events";
import {
  downloadJson,
  formatClock,
  formatTimestamp,
  pluralize,
} from "../lib/format";
import { usePolled } from "../lib/hooks";
import type { AuditEvent } from "../lib/types";

const PAGE_SIZE = 25;

export default function AuditLogs() {
  const [searchParams] = useSearchParams();
  const [query, setQuery] = useState("");
  const [eventType, setEventType] = useState("all");
  const [decision, setDecision] = useState(searchParams.get("decision") ?? "all");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<number | null>(
    searchParams.get("seq") ? Number(searchParams.get("seq")) : null,
  );
  const [live, setLive] = useState(true);

  const events = usePolled(() => api.auditEvents(1000), live ? 6000 : 0);
  const all: AuditEvent[] = events.data?.events ?? [];

  const types = useMemo(
    () => [...new Set(all.map((event) => event.event_type))].sort(),
    [all],
  );

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return all
      .filter((event) => {
        if (eventType !== "all" && event.event_type !== eventType) return false;
        if (decision !== "all") {
          if (event.event_type !== "policy_decision" || event.payload.decision !== decision) {
            return false;
          }
        }
        if (!needle) return true;
        return [
          event.event_type,
          String(event.seq),
          event.event_hash,
          JSON.stringify(event.payload),
        ]
          .join(" ")
          .toLowerCase()
          .includes(needle);
      })
      .sort((a, b) => b.seq - a.seq);
  }, [all, eventType, decision, query]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(page, pageCount - 1);
  const rows = filtered.slice(safePage * PAGE_SIZE, safePage * PAGE_SIZE + PAGE_SIZE);
  const selectedEvent = all.find((event) => event.seq === selected) ?? null;
  const payload = selectedEvent?.payload ?? {};

  return (
    <>
      <PageHeader
        eyebrow="Authoritative record"
        title="Audit Logs"
        subtitle="The SHA-256 hash chain is the source of truth; the graph is a view derived from these same events. Historical events are never editable here."
        actions={
          <div className="header-meta">
            <RefreshNote updatedAt={events.updatedAt} />
            <button
              type="button"
              className="btn btn--ghost btn--sm"
              onClick={() => downloadJson(`agentshield-audit-${Date.now()}.json`, filtered)}
              disabled={filtered.length === 0}
            >
              Export filtered JSON
            </button>
            <button
              type="button"
              className={`btn btn--sm ${live ? "btn--primary" : "btn--ghost"}`}
              onClick={() => setLive((value) => !value)}
              aria-pressed={live}
            >
              {live ? "Live" : "Paused"}
            </button>
          </div>
        }
      />

      {events.error ? <ErrorBanner error={events.error} onRetry={() => void events.refresh()} /> : null}

      <Panel padded={false} className="logs-panel">
        <div className="logs-toolbar">
          <input
            className="input input--search"
            type="search"
            placeholder="Search event, request, actor, tool, hash…"
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setPage(0);
            }}
            aria-label="Search audit events"
          />
          <label className="select-field">
            <span className="select-label">Event type</span>
            <select
              value={eventType}
              onChange={(event) => {
                setEventType(event.target.value);
                setPage(0);
              }}
            >
              <option value="all">All event types</option>
              {types.map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
          </label>
          <label className="select-field">
            <span className="select-label">Decision</span>
            <select
              value={decision}
              onChange={(event) => {
                setDecision(event.target.value);
                setPage(0);
              }}
            >
              <option value="all">All decisions</option>
              <option value="ALLOW">ALLOW</option>
              <option value="APPROVAL">APPROVAL</option>
              <option value="DENY">DENY</option>
            </select>
          </label>
          <span className="graph-count">
            {pluralize(filtered.length, "event")} matched
          </span>
        </div>

        {events.loading && !events.data ? (
          <div className="pad">
            <Loading label="Loading audit events" />
          </div>
        ) : rows.length === 0 ? (
          <div className="pad">
            <EmptyState
              title="No events match"
              message="Clear the filters or submit a tool call from the Agent Console."
            />
          </div>
        ) : (
          <>
            <div className="table-wrap">
              <table className="table table--log">
                <thead>
                  <tr>
                    <th>Seq</th>
                    <th>Timestamp</th>
                    <th>Event</th>
                    <th>Request</th>
                    <th>Tool / operation</th>
                    <th>Decision</th>
                    <th>Reason</th>
                    <th>Event hash</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((event) => {
                    const meta = metaFor(event);
                    return (
                      <tr
                        key={event.seq}
                        className={selected === event.seq ? "row--selected" : ""}
                        onClick={() => setSelected(event.seq)}
                        tabIndex={0}
                        onKeyDown={(keyboard) => {
                          if (keyboard.key === "Enter" || keyboard.key === " ") {
                            keyboard.preventDefault();
                            setSelected(event.seq);
                          }
                        }}
                      >
                        <td className="mono">{event.seq}</td>
                        <td className="nowrap" title={formatTimestamp(event.timestamp)}>
                          {formatClock(event.timestamp)}
                        </td>
                        <td>
                          <span className="event-cell">
                            <i className={`dot dot--${meta.tone}`} />
                            {meta.label}
                          </span>
                        </td>
                        <td className="mono ellipsis" title={String(event.payload.request_id ?? "")}>
                          {String(event.payload.request_id ?? "—")}
                        </td>
                        <td className="mono ellipsis">
                          {event.payload.tool_name
                            ? `${String(event.payload.tool_name)}.${String(event.payload.operation ?? "")}`
                            : "—"}
                        </td>
                        <td>
                          {event.event_type === "policy_decision" ? (
                            <DecisionBadge decision={String(event.payload.decision ?? "") as never} />
                          ) : (
                            <span className="muted">—</span>
                          )}
                        </td>
                        <td className="mono ellipsis">{String(event.payload.reason_code ?? "—")}</td>
                        <td>
                          <Hash value={event.event_hash} />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <div className="pagination">
              <button
                type="button"
                className="btn btn--ghost btn--sm"
                disabled={safePage <= 0}
                onClick={() => setPage(safePage - 1)}
              >
                Previous
              </button>
              <span className="muted">
                Page {safePage + 1} of {pageCount}
              </span>
              <button
                type="button"
                className="btn btn--ghost btn--sm"
                disabled={safePage >= pageCount - 1}
                onClick={() => setPage(safePage + 1)}
              >
                Next
              </button>
            </div>
          </>
        )}
      </Panel>

      {selectedEvent ? (
        <div className="drawer-backdrop" onClick={() => setSelected(null)}>
          <aside
            className="drawer"
            role="dialog"
            aria-label={`Event ${selectedEvent.seq} details`}
            onClick={(event) => event.stopPropagation()}
          >
            <div className="detail-head">
              <div>
                <p className="page-eyebrow">Audit event #{selectedEvent.seq}</p>
                <h2 className="detail-title">{metaFor(selectedEvent).label}</h2>
              </div>
              <button type="button" className="btn btn--ghost btn--xs" onClick={() => setSelected(null)}>
                Close
              </button>
            </div>

            <div className="detail-meta">
              <span className="mono">{formatTimestamp(selectedEvent.timestamp)}</span>
              <Badge tone="muted">immutable record</Badge>
            </div>

            <div className="detail-grid">
              <KeyValue label="Event type" mono>{selectedEvent.event_type}</KeyValue>
              <KeyValue label="Request" mono>{String(payload.request_id ?? "—")}</KeyValue>
              <KeyValue label="Session" mono>{String(payload.session_id ?? "—")}</KeyValue>
              <KeyValue label="Actor" mono>{String(payload.actor_id ?? "—")}</KeyValue>
              <KeyValue label="Tool" mono>{String(payload.tool_name ?? "—")}</KeyValue>
              <KeyValue label="Operation" mono>{String(payload.operation ?? "—")}</KeyValue>
              <KeyValue label="Decision">
                {payload.decision ? (
                  <DecisionBadge decision={String(payload.decision) as never} />
                ) : (
                  <span className="muted">—</span>
                )}
              </KeyValue>
              <KeyValue label="Reason code" mono>{String(payload.reason_code ?? "—")}</KeyValue>
              <KeyValue label="Policy version" mono>{String(payload.policy_version ?? "—")}</KeyValue>
              <KeyValue label="Approval" mono>{String(payload.approval_id ?? "—")}</KeyValue>
            </div>

            {payload.explanation ? (
              <p className="detail-explanation">{String(payload.explanation)}</p>
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
              <div className="detail-section-head">
                <h3 className="detail-subtitle">Structured payload</h3>
                <CopyButton value={JSON.stringify(selectedEvent.payload, null, 2)} label="Copy JSON" />
              </div>
              <JsonBlock value={selectedEvent.payload} maxHeight={260} />
            </div>

            {typeof payload.request_id === "string" ? (
              <div className="detail-actions">
                <Link
                  className="btn btn--primary btn--sm"
                  to={`/graph?request=${encodeURIComponent(payload.request_id)}&focus=${selectedEvent.seq}`}
                >
                  View in graph
                </Link>
              </div>
            ) : null}
          </aside>
        </div>
      ) : null}
    </>
  );
}
