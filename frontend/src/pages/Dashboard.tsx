import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import {
  Badge,
  DecisionBadge,
  EmptyState,
  ErrorBanner,
  Hash,
  Loading,
  PageHeader,
  Panel,
  RefreshNote,
  StatCard,
  StateBadge,
} from "../components/ui";
import { api } from "../lib/api";
import { metaFor } from "../lib/events";
import { formatClock, formatTimestamp, relativeTime, pluralize } from "../lib/format";
import { useNow, usePolled } from "../lib/hooks";
import { groupChains } from "../lib/trace";
import type { AuditEvent } from "../lib/types";

const BUCKETS = 15;
const BUCKET_MS = 2 * 60 * 1000;

type Bucket = { start: number; allow: number; deny: number; approval: number };

export default function Dashboard() {
  const navigate = useNavigate();
  const now = useNow(10000);
  const health = usePolled(() => api.health(), 5000);
  const events = usePolled(() => api.auditEvents(300), 5000);
  const approvals = usePolled(() => api.approvals(), 5000);
  const verify = usePolled(() => api.verify({}), 15000);

  const auditEvents: AuditEvent[] = events.data?.events ?? [];
  const decisions = useMemo(
    () => auditEvents.filter((event) => event.event_type === "policy_decision"),
    [auditEvents],
  );

  const allowed = decisions.filter((event) => event.payload.decision === "ALLOW").length;
  const blocked = decisions.filter((event) => event.payload.decision === "DENY").length;
  const escalated = decisions.filter((event) => event.payload.decision === "APPROVAL").length;
  const executed = auditEvents.filter(
    (event) => event.event_type === "execution_completed" || event.event_type === "execution_recorded",
  ).length;

  const pending = (approvals.data?.approvals ?? []).filter(
    (approval) => approval.state === "PENDING_APPROVAL",
  );

  const chains = useMemo(() => groupChains(auditEvents).chains, [auditEvents]);
  const traces = chains
    .filter((chain) => chain.requestId)
    .slice(-6)
    .reverse();

  const buckets = useMemo<Bucket[]>(() => {
    const end = now;
    const start = end - BUCKETS * BUCKET_MS;
    const list: Bucket[] = Array.from({ length: BUCKETS }, (_, index) => ({
      start: start + index * BUCKET_MS,
      allow: 0,
      deny: 0,
      approval: 0,
    }));
    for (const event of decisions) {
      const time = new Date(event.timestamp).getTime();
      const index = Math.floor((time - start) / BUCKET_MS);
      if (index < 0 || index >= BUCKETS) continue;
      if (event.payload.decision === "ALLOW") list[index].allow += 1;
      else if (event.payload.decision === "DENY") list[index].deny += 1;
      else if (event.payload.decision === "APPROVAL") list[index].approval += 1;
    }
    return list;
  }, [decisions, now]);

  const peak = Math.max(1, ...buckets.map((bucket) => bucket.allow + bucket.deny + bucket.approval));
  const error = events.error ?? approvals.error ?? health.error;
  const recent = [...auditEvents].reverse().slice(0, 8);

  return (
    <>
      <PageHeader
        eyebrow="Security operations"
        title="Dashboard"
        subtitle="Live posture of the enforcement gateway. Every count below is derived from backend audit events and approval records."
        actions={
          <div className="header-meta">
            <RefreshNote updatedAt={events.updatedAt} />
            <button type="button" className="btn btn--ghost btn--sm" onClick={() => void events.refresh()}>
              Refresh
            </button>
          </div>
        }
      />

      {error ? <ErrorBanner error={error} onRetry={() => void events.refresh()} /> : null}

      <div className="stat-grid">
        <StatCard
          label="Allowed"
          value={allowed}
          tone="teal"
          hint={`of ${pluralize(decisions.length, "policy decision")}`}
          onClick={() => navigate("/logs?decision=ALLOW")}
        />
        <StatCard
          label="Blocked"
          value={blocked}
          tone="coral"
          hint="denied before any tool side effect"
          onClick={() => navigate("/logs?decision=DENY")}
        />
        <StatCard
          label="Pending approvals"
          value={pending.length}
          tone="amber"
          hint={`${escalated} escalated to a human in total`}
          onClick={() => navigate("/approvals")}
        />
        <StatCard
          label="Integrity"
          value={verify.data ? (verify.data.valid ? "VALID" : "MISMATCH") : "—"}
          tone={verify.data ? (verify.data.valid ? "purple" : "coral") : "muted"}
          hint={
            verify.data
              ? `${pluralize(verify.data.event_count, "event")} checked · ${
                  verify.updatedAt ? formatClock(verify.updatedAt) : "—"
                }`
              : "running verifier"
          }
          onClick={() => navigate("/integrity")}
        />
      </div>

      <div className="layout-two">
        <Panel
          title="Action activity"
          subtitle={`Policy decisions in 2-minute buckets over the last 30 minutes · source GET /audit/events`}
          actions={
            <div className="legend">
              <span className="legend-item">
                <i className="dot dot--teal" /> allow
              </span>
              <span className="legend-item">
                <i className="dot dot--coral" /> deny
              </span>
              <span className="legend-item">
                <i className="dot dot--amber" /> approval
              </span>
            </div>
          }
        >
          {events.loading && !events.data ? (
            <Loading label="Loading events" />
          ) : decisions.length === 0 ? (
            <EmptyState
              title="No policy decisions recorded yet"
              message="Submit a tool call from the Agent Console, then the graph and logs fill from the audit record."
              action={
                <button type="button" className="btn btn--primary btn--sm" onClick={() => navigate("/console")}>
                  Open Agent Console
                </button>
              }
            />
          ) : (
            <div className="activity">
              <div className="activity-chart" role="img" aria-label="Policy decisions per 2-minute bucket">
                {buckets.map((bucket) => {
                  const total = bucket.allow + bucket.deny + bucket.approval;
                  return (
                    <div
                      key={bucket.start}
                      className="activity-col"
                      title={`${new Date(bucket.start).toLocaleTimeString()} — allow ${bucket.allow}, deny ${bucket.deny}, approval ${bucket.approval}`}
                    >
                      <div className="activity-stack">
                        {bucket.allow > 0 ? (
                          <span
                            className="activity-seg activity-seg--teal"
                            style={{ height: `${(bucket.allow / peak) * 100}%` }}
                          />
                        ) : null}
                        {bucket.deny > 0 ? (
                          <span
                            className="activity-seg activity-seg--coral"
                            style={{ height: `${(bucket.deny / peak) * 100}%` }}
                          />
                        ) : null}
                        {bucket.approval > 0 ? (
                          <span
                            className="activity-seg activity-seg--amber"
                            style={{ height: `${(bucket.approval / peak) * 100}%` }}
                          />
                        ) : null}
                        {total === 0 ? <span className="activity-seg activity-seg--empty" /> : null}
                      </div>
                    </div>
                  );
                })}
              </div>
              <div className="activity-axis">
                <span>{formatClock(buckets[0]?.start)}</span>
                <span>now</span>
              </div>
              <p className="fine-print">
                {pluralize(executed, "tool execution")} completed in this window. Event count is
                scoped to the most recent {auditEvents.length} audit records returned by the API.
              </p>
            </div>
          )}
        </Panel>

        <Panel
          title="Approval queue"
          subtitle={`${pending.length} action${pending.length === 1 ? "" : "s"} awaiting a bound human decision`}
          actions={
            <button type="button" className="btn btn--ghost btn--sm" onClick={() => navigate("/approvals")}>
              Open queue
            </button>
          }
        >
          {pending.length === 0 ? (
            <EmptyState
              title="Nothing pending"
              message="Elevated actions (external sends, confidential transfers) appear here with the exact bound call."
            />
          ) : (
            <ul className="queue">
              {pending.slice(0, 4).map((approval) => (
                <li key={approval.approval_id} className="queue-item">
                  <div className="queue-main">
                    <span className="queue-title">
                      {approval.binding.tool_name}
                      <span className="mono queue-op">.{approval.binding.operation}</span>
                    </span>
                    <span className="queue-target mono">
                      {approval.binding.destination ??
                        approval.binding.resource ??
                        String(approval.binding.arguments.path ?? "—")}
                    </span>
                  </div>
                  <div className="queue-meta">
                    <Badge tone="amber">{approval.binding.data_classification}</Badge>
                    <span className="muted">{relativeTime(approval.created_at, now)}</span>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      <div className="layout-two">
        <Panel
          title="Recent execution traces"
          subtitle="One chain per request, reconstructed from recorded events"
          actions={
            <button type="button" className="btn btn--ghost btn--sm" onClick={() => navigate("/graph")}>
              View graph
            </button>
          }
          padded={false}
        >
          {traces.length === 0 ? (
            <div className="pad">
              <EmptyState title="No traces yet" message="Submit a call to record the first trace." />
            </div>
          ) : (
            <ul className="trace-list">
              {traces.map((chain) => {
                const last = chain.events[chain.events.length - 1];
                const decisionEvent = chain.events.find((event) => event.event_type === "policy_decision");
                const decision = decisionEvent ? String(decisionEvent.payload.decision ?? "") : null;
                return (
                  <li key={chain.id}>
                    <button
                      type="button"
                      className="trace-row"
                      onClick={() => navigate(`/graph?request=${encodeURIComponent(chain.id)}`)}
                    >
                      <span className="trace-rail" aria-hidden="true">
                        <i className={`dot dot--${decision === "DENY" ? "coral" : decision === "APPROVAL" ? "amber" : "teal"}`} />
                      </span>
                      <span className="trace-main">
                        <span className="trace-title mono">{chain.requestId}</span>
                        <span className="trace-sub">
                          {chain.session} · {pluralize(chain.events.length, "event")} ·{" "}
                          {String(decisionEvent?.payload.tool_name ?? "tool call")}{" "}
                          {String(decisionEvent?.payload.operation ?? "")}
                        </span>
                      </span>
                      <span className="trace-side">
                        <DecisionBadge decision={decision as "ALLOW" | "DENY" | "APPROVAL" | null} />
                        <span className="muted">{formatClock(last?.timestamp)}</span>
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </Panel>

        <Panel title="Integrity summary" subtitle="SHA-256 hash-chain verification" actions={
          <button type="button" className="btn btn--ghost btn--sm" onClick={() => void verify.refresh()}>
            Re-verify
          </button>
        }>
          {verify.error ? (
            <ErrorBanner error={verify.error} onRetry={() => void verify.refresh()} />
          ) : !verify.data ? (
            <Loading label="Verifying chain" />
          ) : (
            <div className="stack">
              <div className="integrity-line">
                <StateBadge state={verify.data.valid ? "VALID" : "FAILED"} />
                <span className="muted">
                  {pluralize(verify.data.event_count, "event")} ·{" "}
                  {verify.updatedAt ? `checked ${relativeTime(verify.updatedAt / 1000, now)}` : "—"}
                </span>
              </div>
              <div className="kv">
                <span className="kv-label">chain head</span>
                <Hash value={verify.data.head} />
              </div>
              {verify.data.failures.length > 0 ? (
                <ul className="failure-list">
                  {verify.data.failures.map((failure) => (
                    <li key={failure}>{failure}</li>
                  ))}
                </ul>
              ) : (
                <p className="fine-print">
                  This proves internal consistency for the checked range, not completeness. Pin an
                  event count or head as a trust anchor on the Integrity page to detect truncation.
                </p>
              )}
            </div>
          )}
        </Panel>
      </div>

      <Panel
        title="Recent security events"
        subtitle="Authoritative audit record, newest first"
        actions={
          <button type="button" className="btn btn--ghost btn--sm" onClick={() => navigate("/logs")}>
            Open logs
          </button>
        }
        padded={false}
      >
        {recent.length === 0 ? (
          <div className="pad">
            <EmptyState title="Audit trail is empty" message="Every action writes an event here." />
          </div>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Seq</th>
                  <th>Time</th>
                  <th>Event</th>
                  <th>Request</th>
                  <th>Decision</th>
                  <th>Reason</th>
                  <th>Hash</th>
                </tr>
              </thead>
              <tbody>
                {recent.map((event) => {
                  const meta = metaFor(event);
                  return (
                    <tr key={event.seq}>
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
                      <td>
                        {event.event_type === "policy_decision" ? (
                          <DecisionBadge decision={String(event.payload.decision ?? "") as never} />
                        ) : (
                          <span className="muted">—</span>
                        )}
                      </td>
                      <td className="mono ellipsis" title={String(event.payload.reason_code ?? "")}>
                        {String(event.payload.reason_code ?? "—")}
                      </td>
                      <td>
                        <Hash value={event.event_hash} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </>
  );
}
