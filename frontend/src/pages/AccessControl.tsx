import {
  Badge,
  DecisionBadge,
  EmptyState,
  ErrorBanner,
  Loading,
  PageHeader,
  Panel,
  RefreshNote,
} from "../components/ui";
import { api } from "../lib/api";
import { pluralize } from "../lib/format";
import { usePolled } from "../lib/hooks";

export default function AccessControl() {
  const policy = usePolled(() => api.policy(), 15000);

  if (policy.error) {
    return (
      <>
        <PageHeader eyebrow="Governance" title="Access Control" />
        <ErrorBanner error={policy.error} onRetry={() => void policy.refresh()} />
      </>
    );
  }
  if (!policy.data) {
    return (
      <>
        <PageHeader eyebrow="Governance" title="Access Control" />
        <Loading label="Loading policy" />
      </>
    );
  }

  const { rules, config, tools } = policy.data;

  return (
    <>
      <PageHeader
        eyebrow="Governance"
        title="Access Control"
        subtitle="Tool registration and governance policy are separate. Registering a tool grants nothing; only an explicit rule can permit an action, and unmatched actions fail closed."
        actions={<RefreshNote updatedAt={policy.updatedAt} />}
      />

      <div className="notice notice--panel">
        <strong>Read-only view.</strong> This prototype's policy is versioned code
        (<code className="mono">{policy.data.policy_version}</code>), not a runtime-editable document.
        There is no publish or draft endpoint on the backend, so this console deliberately does not
        offer one — a policy editor that could not actually change enforcement would misrepresent
        the system. Changing policy means changing and re-testing the rule set server-side.
      </div>

      <div className="layout-two">
        <Panel
          title="Registered tools"
          subtitle={`${pluralize(Object.keys(tools).length, "tool")} · registration is not authorization`}
        >
          <ul className="tool-grid">
            {Object.entries(tools).map(([name, spec]) => (
              <li key={name} className="tool-card">
                <div className="tool-head">
                  <span className="mono tool-name">{name}</span>
                  <Badge tone="blue">registered</Badge>
                </div>
                <p className="tool-desc">{spec.description}</p>
                <div className="tool-ops">
                  {spec.operations.map((operation) => (
                    <span key={operation} className="chip mono">
                      {operation}({spec.required_args[operation]?.join(", ") ?? ""})
                    </span>
                  ))}
                </div>
              </li>
            ))}
          </ul>
        </Panel>

        <Panel title="Frozen policy parameters" subtitle="Data the rule predicates read">
          <div className="stack-tight">
            <div className="kv">
              <span className="kv-label">policy version</span>
              <code className="mono">{policy.data.policy_version}</code>
            </div>
            <div className="kv">
              <span className="kv-label">canonicalization</span>
              <code className="mono">{policy.data.canonicalization_version}</code>
            </div>
            <div className="kv">
              <span className="kv-label">readable roots</span>
              <code className="mono">{config.readable_roots.join(", ")}</code>
            </div>
            <div className="kv">
              <span className="kv-label">restricted roots</span>
              <code className="mono">{config.restricted_roots.join(", ") || "—"}</code>
            </div>
            <div className="kv">
              <span className="kv-label">internal domains</span>
              <code className="mono">{config.internal_domains.join(", ")}</code>
            </div>
            <div className="kv">
              <span className="kv-label">approved destinations</span>
              <code className="mono">{config.approved_destinations.join(", ") || "—"}</code>
            </div>
            <div className="kv">
              <span className="kv-label">external sends</span>
              <span>
                {config.require_approval_for_external_send
                  ? "require human approval"
                  : "allow by configuration"}
              </span>
            </div>
          </div>
          <div className="detail-section">
            <h3 className="detail-subtitle">Hard-deny reason codes</h3>
            <p className="fine-print">
              None of these can be overridden by approving an action.
            </p>
            <div className="chip-row">
              {policy.data.hard_deny_reason_codes.map((code) => (
                <span key={code} className="chip chip--coral mono">
                  {code}
                </span>
              ))}
            </div>
          </div>
        </Panel>
      </div>

      <Panel
        title="Ordered rule set"
        subtitle={policy.data.rule_order}
        padded={false}
      >
        {rules.length === 0 ? (
          <div className="pad">
            <EmptyState title="No rules returned" />
          </div>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th className="narrow">#</th>
                  <th>Rule</th>
                  <th>Decision</th>
                  <th>Reason code</th>
                  <th>Explanation</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={rule.name}>
                    <td className="mono">{rule.index}</td>
                    <td className="mono">{rule.name}</td>
                    <td>
                      <DecisionBadge decision={rule.decision} />
                    </td>
                    <td className="mono">{rule.reason_code}</td>
                    <td className="wrap">{rule.explanation}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </>
  );
}
