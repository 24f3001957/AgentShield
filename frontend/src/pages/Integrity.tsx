import { useState } from "react";
import {
  Badge,
  EmptyState,
  ErrorBanner,
  Hash,
  Loading,
  PageHeader,
  Panel,
  RefreshNote,
  StateBadge,
} from "../components/ui";
import { api } from "../lib/api";
import {
  downloadJson,
  formatClock,
  formatTimestamp,
  messageOf,
  pluralize,
} from "../lib/format";
import { usePolled } from "../lib/hooks";
import type { VerifyResult } from "../lib/types";

export default function Integrity() {
  const events = usePolled(() => api.auditEvents(400), 10000);
  const [expectedCount, setExpectedCount] = useState("");
  const [expectedHead, setExpectedHead] = useState("");
  const [record, setRecord] = useState(false);
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const total = events.data?.count ?? 0;
  const chain = events.data?.events ?? [];

  async function verify() {
    setBusy(true);
    setError(null);
    try {
      const parsed = expectedCount.trim() ? Number(expectedCount) : undefined;
      if (parsed !== undefined && (!Number.isFinite(parsed) || parsed < 1)) {
        throw new Error("expected count must be a positive integer");
      }
      const next = await api.verify({
        expectedCount: parsed,
        expectedHead: expectedHead.trim() || undefined,
        record,
      });
      setResult(next);
    } catch (caught) {
      setError(messageOf(caught));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="Evidence"
        title="Integrity"
        subtitle="SHA-256 is a hash function, not encryption. The chain is tamper-evident, not tamper-proof: an attacker who can rewrite the whole database can recompute every hash."
        actions={
          <div className="header-meta">
            <RefreshNote updatedAt={events.updatedAt} />
            <Badge tone="purple">{pluralize(total, "stored event")}</Badge>
          </div>
        }
      />

      <div className="layout-two layout-two--wide-left">
        <Panel title="Run verification" subtitle="Optionally pin a trust anchor from outside the store">
          <div className="form-grid">
            <label className="field">
              <span className="field-label">Expected event count (optional anchor)</span>
              <input
                className="input mono"
                inputMode="numeric"
                placeholder={total ? String(total) : "e.g. 42"}
                value={expectedCount}
                onChange={(event) => setExpectedCount(event.target.value)}
              />
            </label>
            <label className="field">
              <span className="field-label">Expected chain head (optional anchor)</span>
              <input
                className="input mono"
                placeholder="64-hex SHA-256 head"
                value={expectedHead}
                onChange={(event) => setExpectedHead(event.target.value)}
                maxLength={64}
              />
            </label>
          </div>
          <label className="checkbox">
            <input
              type="checkbox"
              checked={record}
              onChange={(event) => setRecord(event.target.checked)}
            />
            <span>Record this verification as an audit event</span>
          </label>
          <div className="button-row">
            <button type="button" className="btn btn--primary" onClick={() => void verify()} disabled={busy}>
              {busy ? "Verifying…" : "Verify chain"}
            </button>
            <button
              type="button"
              className="btn btn--ghost"
              disabled={!result}
              onClick={() => result && downloadJson(`agentshield-verification-${Date.now()}.json`, result)}
            >
              Export report
            </button>
          </div>
          <p className="fine-print">
            Without an externally held count or head, a truncated-but-consistent chain still
            verifies. With one, truncation and head substitution are detected.
          </p>
          {error ? <ErrorBanner error={error} /> : null}
        </Panel>

        <Panel title="Latest result" subtitle="Actual verifier output, not a summary badge">
          {!result ? (
            <EmptyState
              title="No verification run in this session"
              message="Run the verifier to recompute every stored hash and check sequence continuity."
            />
          ) : (
            <div className="stack">
              <div className="integrity-line">
                <StateBadge state={result.valid ? "VALID" : "MISMATCH"} />
                <span className="muted">
                  {pluralize(result.event_count, "event")} checked ·{" "}
                  {result.trust_anchor.expected_count ? "anchored by count" : "no count anchor"}
                  {result.trust_anchor.expected_head ? " + head" : ""}
                </span>
              </div>
              <div className="kv">
                <span className="kv-label">chain head</span>
                <Hash value={result.head} />
              </div>
              {result.failures.length > 0 ? (
                <div>
                  <h3 className="detail-subtitle">Failures</h3>
                  <ul className="failure-list">
                    {result.failures.map((failure) => (
                      <li key={failure}>{failure}</li>
                    ))}
                  </ul>
                </div>
              ) : (
                <p className="fine-print">No mismatches, sequence gaps or linkage errors found.</p>
              )}
              <p className="fine-print">{result.trust_anchor.note}</p>
            </div>
          )}
        </Panel>
      </div>

      <Panel
        title="Recent chain links"
        subtitle="Newest events first; each hash covers the previous hash and the canonical event body"
        padded={false}
      >
        {events.loading && !events.data ? (
          <div className="pad">
            <Loading label="Loading chain" />
          </div>
        ) : chain.length === 0 ? (
          <div className="pad">
            <EmptyState title="Chain is empty" message="The genesis hash is the 64-zero head of an empty log." />
          </div>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Seq</th>
                  <th>Recorded at</th>
                  <th>Event</th>
                  <th>Previous hash</th>
                  <th>Event hash</th>
                </tr>
              </thead>
              <tbody>
                {[...chain]
                  .reverse()
                  .slice(0, 40)
                  .map((event) => (
                    <tr key={event.seq}>
                      <td className="mono">{event.seq}</td>
                      <td className="nowrap" title={formatTimestamp(event.timestamp)}>
                        {formatClock(event.timestamp)}
                      </td>
                      <td className="mono">{event.event_type}</td>
                      <td>
                        <Hash value={event.prev_hash} />
                      </td>
                      <td>
                        <Hash value={event.event_hash} />
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Panel title="What this screen does and does not prove">
        <ul className="rules-list">
          <li>
            <strong>Detects:</strong> edited events, interior deletion, reordering and, with a pinned
            anchor, a removed tail.
          </li>
          <li>
            <strong>Does not detect:</strong> a full rewrite where every hash is recomputed by an
            attacker with write access to the store.
          </li>
          <li>
            <strong>Not claimed:</strong> completeness, legal admissibility, non-repudiation or
            “tamper-proof” status.
          </li>
        </ul>
      </Panel>
    </>
  );
}
