import { Badge, ErrorBanner, Loading, Panel } from "./ui";
import { api } from "../lib/api";
import { usePolled } from "../lib/hooks";
import { pluralize } from "../lib/format";

function pct(value: number | null): string {
  if (value === null) return "N/A";
  return `${(value * 100).toFixed(1)}%`;
}

export function ClassifierPanel() {
  const classifier = usePolled(() => api.classifier(), 30000);
  const doc = classifier.data;

  return (
    <Panel
      title="Advisory classifier"
      subtitle="TF-IDF features + multinomial logistic regression, trained in-process from the bundled fixtures"
      actions={
        doc ? (
          <div className="chip-row">
            <Badge tone="purple">{doc.model_version}</Badge>
            <Badge tone="muted">{doc.dataset_version}</Badge>
          </div>
        ) : null
      }
    >
      {classifier.error ? (
        <ErrorBanner error={classifier.error} onRetry={() => void classifier.refresh()} />
      ) : !doc ? (
        <Loading label="Loading model card" />
      ) : (
        <div className="stack">
          <div className="notice notice--panel">
            <strong>Authority:</strong> {doc.authority}
          </div>

          <div className="detail-grid">
            <div className="kv">
              <span className="kv-label">decision accuracy</span>
              <span className="kv-value mono">{pct(doc.metrics.accuracy)}</span>
            </div>
            <div className="kv">
              <span className="kv-label">exact match</span>
              <span className="kv-value mono">{pct(doc.metrics.exact_match_accuracy)}</span>
            </div>
            <div className="kv">
              <span className="kv-label">macro F1</span>
              <span className="kv-value mono">
                {doc.metrics.macro_f1 === null ? "N/A" : doc.metrics.macro_f1.toFixed(3)}
              </span>
            </div>
            <div className="kv">
              <span className="kv-label">abstention rate</span>
              <span className="kv-value mono">{pct(doc.metrics.abstention_rate)}</span>
            </div>
            <div className="kv">
              <span className="kv-label">false positive / negative</span>
              <span className="kv-value mono">
                {doc.metrics.false_positive} / {doc.metrics.false_negative}
              </span>
            </div>
            <div className="kv">
              <span className="kv-label">dataset</span>
              <span className="kv-value mono">
                {pluralize(doc.metrics.dataset_size, "fixture")} · {doc.metrics.train_size} train ·{" "}
                {doc.metrics.test_size} test
              </span>
            </div>
            <div className="kv">
              <span className="kv-label">thresholds</span>
              <span className="kv-value mono">
                confidence ≥ {doc.thresholds.confidence} · margin ≥ {doc.thresholds.margin} · oov ≥{" "}
                {doc.thresholds.oov_ratio}
              </span>
            </div>
            <div className="kv">
              <span className="kv-label">features</span>
              <span className="kv-value mono">{doc.metrics.feature_count}</span>
            </div>
          </div>

          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Class</th>
                  <th>Support</th>
                  <th>Precision</th>
                  <th>Recall</th>
                  <th>F1</th>
                  <th>TP / FP / FN</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(doc.metrics.per_class).map(([label, row]) => (
                  <tr key={label}>
                    <td>
                      <Badge
                        tone={
                          label === "allow"
                            ? "teal"
                            : label === "deny"
                              ? "coral"
                              : label === "approval"
                                ? "amber"
                                : "muted"
                        }
                      >
                        {label}
                      </Badge>
                    </td>
                    <td className="mono">{row.support}</td>
                    <td className="mono">{row.precision === null ? "N/A" : row.precision.toFixed(3)}</td>
                    <td className="mono">{row.recall === null ? "N/A" : row.recall.toFixed(3)}</td>
                    <td className="mono">{row.f1 === null ? "N/A" : row.f1.toFixed(3)}</td>
                    <td className="mono">
                      {row.tp} / {row.fp} / {row.fn}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="table-wrap">
            <table className="table">
              <caption className="table-caption">
                Confusion matrix · {doc.metrics.split}
              </caption>
              <thead>
                <tr>
                  <th>expected ↓ / predicted →</th>
                  {Object.keys(doc.metrics.confusion_matrix).map((label) => (
                    <th key={label}>{label}</th>
                  ))}
                  <th>abstain</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(doc.metrics.confusion_matrix).map(([expected, row]) => (
                  <tr key={expected}>
                    <td className="mono">{expected}</td>
                    {Object.keys(doc.metrics.confusion_matrix).map((label) => (
                      <td key={label} className="mono">
                        {row[label] ?? 0}
                      </td>
                    ))}
                    <td className="mono">{row.abstain ?? 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <p className="fine-print">
            {doc.metrics.accuracy_definition}. {doc.metrics.macro_f1_note}. "Ambiguous" fixtures are
            underspecified calls where abstaining is the intended behaviour. Dataset source:{" "}
            {doc.dataset_source}
          </p>
        </div>
      )}
    </Panel>
  );
}
