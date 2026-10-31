import { useEffect, useState } from "react";
import {
  Badge,
  EmptyState,
  ErrorBanner,
  Loading,
  PageHeader,
  Panel,
  RefreshNote,
} from "../components/ui";
import { ApiError, api } from "../lib/api";
import { formatRate, formatTimestamp, messageOf, pluralize } from "../lib/format";
import type { EvaluationResults, Metric } from "../lib/types";

function isPaired(
  value: Metric | { firewall_off: Metric; firewall_on: Metric },
): value is { firewall_off: Metric; firewall_on: Metric } {
  return typeof value === "object" && value !== null && "firewall_off" in value;
}

function metricLabel(key: string): string {
  return key.replaceAll("_", " ");
}

function RateCell({ metric }: { metric: Metric }) {
  return (
    <div className="rate-cell">
      <span className="rate-value">{formatRate(metric.rate)}</span>
      <span className="muted mono">
        {metric.numerator ?? "—"} / {metric.denominator ?? "—"}
      </span>
    </div>
  );
}

export default function Evaluation() {
  const [results, setResults] = useState<EvaluationResults | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [updatedAt, setUpdatedAt] = useState<number | null>(null);

  useEffect(() => {
    let alive = true;
    api
      .evaluationResults()
      .then((data) => {
        if (alive) {
          setResults(data);
          setUpdatedAt(Date.now());
        }
      })
      .catch((caught: unknown) => {
        if (!alive) return;
        if (caught instanceof ApiError && caught.status === 404) setResults(null);
        else setError(messageOf(caught));
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, []);

  async function run() {
    setRunning(true);
    setError(null);
    try {
      const data = await api.runEvaluation();
      setResults(data);
      setUpdatedAt(Date.now());
    } catch (caught) {
      setError(messageOf(caught));
    } finally {
      setRunning(false);
    }
  }

  const metrics = results ? Object.entries(results.metrics) : [];

  return (
    <>
      <PageHeader
        eyebrow="Measurement"
        title="Evaluation"
        subtitle="The same labelled fixtures run with the firewall OFF (raw mock primitives) and ON (through the gateway). Rates are computed from per-case rows, with numerators and denominators shown."
        actions={
          <div className="header-meta">
            <RefreshNote updatedAt={updatedAt} />
            <button type="button" className="btn btn--primary btn--sm" onClick={() => void run()} disabled={running}>
              {running ? "Running both conditions…" : "Run evaluation"}
            </button>
            {results ? (
              <a className="btn btn--ghost btn--sm" href={api.evaluationExportUrl()} download>
                Export JSON
              </a>
            ) : null}
          </div>
        }
      />

      {error ? <ErrorBanner error={error} /> : null}

      {loading ? (
        <Loading label="Loading evaluation results" />
      ) : !results ? (
        <EmptyState
          title="No evaluation run recorded"
          message="Run the fixed fixture set to produce raw case outcomes and paired metrics. This executes mock tools only, seeded from a temporary database."
          action={
            <button type="button" className="btn btn--primary" onClick={() => void run()} disabled={running}>
              {running ? "Running…" : "Run evaluation now"}
            </button>
          }
        />
      ) : (
        <>
          <div className="notice notice--panel">
            <strong>Fixture provenance.</strong> {results.fixture_provenance}{" "}
            <span className="muted">
              {pluralize(results.fixture_count, "case")} · run{" "}
              <code className="mono">{results.run_id}</code> · {formatTimestamp(results.created_at)}
            </span>
          </div>

          <Panel title="Paired metrics" subtitle="Firewall OFF vs firewall ON" padded={false}>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Metric</th>
                    <th>Firewall OFF</th>
                    <th>Firewall ON</th>
                    <th>Scope note</th>
                  </tr>
                </thead>
                <tbody>
                  {metrics.map(([key, value]) => {
                    if (isPaired(value)) {
                      return (
                        <tr key={key}>
                          <td className="metric-name">{metricLabel(key)}</td>
                          <td>
                            <RateCell metric={value.firewall_off} />
                          </td>
                          <td>
                            <RateCell metric={value.firewall_on} />
                          </td>
                          <td className="wrap muted">{value.firewall_on.note}</td>
                        </tr>
                      );
                    }
                    return (
                      <tr key={key}>
                        <td className="metric-name">{metricLabel(key)}</td>
                        <td className="muted">not measured</td>
                        <td>
                          <RateCell metric={value} />
                        </td>
                        <td className="wrap muted">{value.note}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </Panel>

          <div className="layout-two">
            <Panel title="Firewall ON cases" subtitle="Each row is one labelled fixture through the gateway" padded={false}>
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Case</th>
                      <th>Expected</th>
                      <th>Observed</th>
                      <th>Accurate</th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.conditions.firewall_on.cases.map((item) => (
                      <tr key={item.case_id}>
                        <td>
                          <span className="mono case-id">{item.case_id}</span>
                          <span className="case-desc">{item.description}</span>
                        </td>
                        <td className="mono">
                          {item.expected_decision}
                          <span className="case-desc">{item.expected_reason_code}</span>
                        </td>
                        <td className="mono">
                          {item.actual_decision}
                          <span className="case-desc">{item.actual_reason_code ?? "—"}</span>
                        </td>
                        <td>
                          <Badge tone={item.decision_correct ? "teal" : "coral"}>
                            {item.decision_correct ? "match" : "mismatch"}
                          </Badge>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Panel>

            <Panel title="Firewall OFF cases" subtitle="Baseline harness, no policy" padded={false}>
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Case</th>
                      <th>Expected</th>
                      <th>Observed</th>
                      <th>Side effect</th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.conditions.firewall_off.cases.map((item) => (
                      <tr key={item.case_id}>
                        <td>
                          <span className="mono case-id">{item.case_id}</span>
                          <span className="case-desc">{item.description}</span>
                        </td>
                        <td className="mono">{item.expected_decision}</td>
                        <td>
                          <Badge tone="muted">{item.actual_decision}</Badge>
                        </td>
                        <td>
                          <Badge tone={item.side_effect ? "coral" : "teal"}>
                            {item.side_effect ? "occurred" : "none"}
                          </Badge>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Panel>
          </div>

          <Panel title="Honesty notes" subtitle="Read before citing any number">
            <ul className="rules-list">
              {results.notes.map((note) => (
                <li key={note}>{note}</li>
              ))}
            </ul>
          </Panel>
        </>
      )}
    </>
  );
}
