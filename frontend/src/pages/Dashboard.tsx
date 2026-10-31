import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Badge,
  DecisionBadge,
  EmptyState,
  ErrorBanner,
  Hash,
  KeyValue,
  Loading,
  PageHeader,
  Panel,
  RefreshNote,
  StatCard,
  StateBadge,
} from "../components/ui";
import { api } from "../lib/api";
import { useAppState } from "../lib/appState";
import { metaFor } from "../lib/events";
import { formatClock, formatTimestamp, messageOf, relativeTime, pluralize } from "../lib/format";
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
  const metrics = usePolled(() => api.metrics(), 5000);
  const { latestSimulation, setLatestSimulation, dataVersion, ask } = useAppState();
  const [runBusy, setRunBusy] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);

  useEffect(() => {
    if (!dataVersion) return;
    void events.refresh();
    void metrics.refresh();
    void approvals.refresh();
    void verify.refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dataVersion]);

  useEffect(() => {
    if (latestSimulation) return;
    api
      .latestSimulation()
      .then((run) => setLatestSimulation(run))
      .catch(() => undefined);
  }, [latestSimulation, setLatestSimulation]);

  async function runAttack() {
    if (runBusy) return;
    setRunBusy(true);
    setRunError(null);
    try {
      const run = await api.runSecretRead();
      setLatestSimulation(run);
      void events.refresh();
      void metrics.refresh();
      void verify.refresh();
    } catch (caught) {
      setRunError(messageOf(caught));
    } finally {
      setRunBusy(false);
    }
  }

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

      <div className="stat-grid stat-grid--four">
        <StatCard
          label="Unauthorized executions"
          value={metrics.data ? metrics.data.unauthorized_executions : "—"}
          tone="teal"
          hint="execution rows whose policy decision was DENY — should always be 0"
        />
        <StatCard
          label="Simulation runs"
          value={metrics.data ? metrics.data.simulations.count : "—"}
          tone="blue"
          hint={
            metrics.data?.simulations.latest
              ? `latest: ${metrics.data.simulations.latest.outcome} · ${metrics.data.simulations.latest.reason_code ?? "—"}`
              : "no scenario executed yet"
          }
          onClick={() => navigate("/graph")}
        />
        <StatCard
          label="Advisory macro F1"
          value={
            metrics.data?.classifier.macro_f1 != null
              ? metrics.data.classifier.macro_f1.toFixed(2)
              : "N/A"
          }
          tone="purple"
          hint={
            metrics.data
              ? `held-out ${metrics.data.classifier.test_size} fixtures · ${(
                  metrics.data.classifier.abstention_rate * 100
                ).toFixed(0)}% abstained`
              : "model card loading"
          }
          onClick={() => navigate("/evaluation")}
        />
        <StatCard
          label="Tool calls recorded"
          value={metrics.data ? metrics.data.tool_calls : "—"}
          tone="muted"
          hint={metrics.data ? `${metrics.data.executions} reached the executor` : "backend metrics"}
          onClick={() => navigate("/logs")}
        />
      </div>

      <div className="layout-two">
        <Panel
          title="Secret-read attack"
          subtitle="Reads a confidential file, then attempts external e-mail with its provenance"
          actions={
            <button
              type="button"
              className="btn btn--primary btn--sm"
              onClick={() => void runAttack()}
              disabled={runBusy}
            >
              {runBusy ? "Running…" : "Run attack"}
            </button>
          }
        >
          {runError ? <ErrorBanner error={runError} /> : null}
          {!latestSimulation ? (
            <EmptyState
              title="No simulation yet"
              message="The assistant and this button both call POST /simulations/secret-read, which runs the scenario through the real gateway."
              action={
                <div className="button-row">
                  <button type="button" className="btn btn--primary btn--sm" onClick={() => void runAttack()} disabled={runBusy}>
                    Run secret-read attack
                  </button>
                  <button type="button" className="btn btn--ghost btn--sm" onClick={() => ask("Run the secret-read attack")}>
                    Ask the assistant
                  </button>
                </div>
              }
            />
          ) : (
            <div className="stack">
              <div className="response-head">
                <DecisionBadge decision={latestSimulation.result.decision} />
                <Badge tone={latestSimulation.result.side_effect ? "coral" : "teal"}>
                  {latestSimulation.result.side_effect ? "side effect" : "no side effect"}
                </Badge>
                <span className="mono muted">
                  {String(latestSimulation.result.reason_code ?? "—")}
                </span>
              </div>
              <p className="detail-explanation">
                {latestSimulation.result.explanation ?? "No explanation recorded."}
              </p>
              <div className="detail-grid">
                <KeyValue label="Blocked at" mono>
                  {latestSimulation.result.blocked_at ?? "no block"}
                </KeyValue>
                <KeyValue label="Executor" mono>
                  {latestSimulation.result.executed ? "ran the action" : "never reached"}
                </KeyValue>
                <KeyValue label="Mock outbox" mono>
                  {latestSimulation.result.outbox_before} → {latestSimulation.result.outbox_after}
                </KeyValue>
                <KeyValue label="Run" mono>
                  {latestSimulation.run_id}
                </KeyValue>
              </div>
              <div className="button-row">
                <button
                  type="button"
                  className="btn btn--primary btn--sm"
                  onClick={() => navigate(`/graph?run=${encodeURIComponent(latestSimulation.run_id)}`)}
                >
                  Open animated path
                </button>
                <button
                  type="button"
                  className="btn btn--ghost btn--sm"
                  onClick={() =>
                    navigate(
                      `/logs?request=${encodeURIComponent(latestSimulation.result.request_id)}`,
                    )
                  }
                >
                  Inspect audit events
                </button>
              </div>
            </div>
          )}
        </Panel>

        <Panel
          title="Advisory classifier"
          subtitle="TF-IDF + logistic regression · cannot authorize or block"
          actions={
            <button type="button" className="btn btn--ghost btn--sm" onClick={() => navigate("/evaluation")}>
              Model card
            </button>
          }
        >
          {!metrics.data ? (
            <Loading label="Loading model card" />
          ) : (
            <div className="stack">
              <div className="response-head">
                <Badge tone="purple">{metrics.data.classifier.model_version}</Badge>
                <span className="muted mono">{metrics.data.classifier.dataset_version}</span>
              </div>
              <div className="detail-grid">
                <KeyValue label="Decision accuracy" mono>
                  {(metrics.data.classifier.accuracy * 100).toFixed(1)}%
                </KeyValue>
                <KeyValue label="Macro F1" mono>
                  {metrics.data.classifier.macro_f1?.toFixed(3) ?? "N/A"}
                </KeyValue>
                <KeyValue label="Abstention rate" mono>
                  {(metrics.data.classifier.abstention_rate * 100).toFixed(1)}%
                </KeyValue>
                <KeyValue label="Fixtures" mono>
                  {metrics.data.classifier.dataset_size} total · {metrics.data.classifier.test_size} held out
                </KeyValue>
                <KeyValue label="False positives" mono>
                  {metrics.data.classifier.false_positive}
                </KeyValue>
                <KeyValue label="False negatives" mono>
                  {metrics.data.classifier.false_negative}
                </KeyValue>
              </div>
              <p className="fine-print">
                Custom fixture set authored from the policy scenarios — not an external benchmark.
                Abstentions fall back to the deterministic policy, which remains authoritative.
              </p>
            </div>
          )}
        </Panel>
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
