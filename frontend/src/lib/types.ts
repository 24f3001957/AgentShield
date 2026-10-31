/** Types mirroring the FastAPI JSON contracts in agentshield/api.py. */

export type Decision = "ALLOW" | "DENY" | "APPROVAL";
export type Classification = "public" | "internal" | "confidential" | "restricted";

export type ToolSpec = {
  description: string;
  operations: string[];
  required_args: Record<string, string[]>;
};

export type Health = {
  status: string;
  policy_version: string;
  audit_events: number;
  tools: Record<string, ToolSpec>;
};

export type ToolCallSummary = {
  request_id: string;
  state: string;
  decision: Decision | null;
  reason_code: string | null;
  approval_id: string | null;
  execution_id: string | null;
  updated_at: number;
};

export type AuditEvent = {
  seq: number;
  event_type: string;
  payload: Record<string, unknown>;
  prev_hash: string;
  event_hash: string;
  timestamp: string;
};

export type ApprovalBinding = {
  actor_id: string;
  session_id: string;
  tool_name: string;
  operation: string;
  arguments: Record<string, unknown>;
  resource: string | null;
  destination: string | null;
  data_classification: Classification;
  provenance: string[];
  policy_version: string;
  canonicalization_version: string;
};

export type Approval = {
  approval_id: string;
  request_id: string;
  fingerprint: string;
  binding: ApprovalBinding;
  state:
    | "PENDING_APPROVAL"
    | "APPROVED"
    | "REJECTED"
    | "REVALIDATED"
    | "CONSUMED"
    | "EXECUTED"
    | "EXPIRED";
  requested_by: string;
  approver: string | null;
  created_at: number;
  expires_at: number;
  decided_at: number | null;
  consumed_at: number | null;
  executed_at: number | null;
};

export type ExecutionResult = {
  execution_id: string;
  request_id: string;
  authorization_id: string;
  tool_name: string;
  operation: string;
  outcome: string;
  summary: string;
  output: Record<string, unknown>;
  error: string | null;
};

export type GatewayResponse = {
  request_id: string;
  status: string;
  decision: Decision | null;
  reason_code: string | null;
  policy_version: string;
  explanation: string;
  approval: Approval | null;
  result: ExecutionResult | null;
  detail: string | null;
};

export type ToolCallDetail = {
  request_id: string;
  state: string;
  decision: Decision | null;
  reason_code: string | null;
  policy_version: string | null;
  approval_id: string | null;
  authorization_id: string | null;
  execution_id: string | null;
  detail: string | null;
  created_at: number;
  updated_at: number;
  execution?: {
    execution_id: string;
    outcome: string;
    summary: string;
    error: string | null;
    executed_at: number;
  };
  approval?: Approval | null;
};

export type VerifyResult = {
  valid: boolean;
  event_count: number;
  head: string;
  failures: string[];
  trust_anchor: {
    expected_count: number | null;
    expected_head: string | null;
    note: string;
  };
};

export type PolicyRule = {
  index: number;
  name: string;
  decision: Decision;
  reason_code: string;
  explanation: string;
};

export type PolicyDoc = {
  policy_version: string;
  canonicalization_version: string;
  rule_order: string;
  hard_deny_reason_codes: string[];
  config: {
    approved_destinations: string[];
    internal_domains: string[];
    internal_roots: string[];
    public_roots: string[];
    readable_roots: string[];
    restricted_roots: string[];
    require_approval_for_external_send: boolean;
  };
  rules: PolicyRule[];
  tools: Record<string, ToolSpec>;
};

export type Metric = {
  numerator: number | null;
  denominator: number | null;
  rate: number | "N/A" | "Not yet measured";
  condition: string;
  note: string;
};

export type EvalCase = {
  case_id: string;
  category: "malicious" | "benign";
  description: string;
  expected_decision: string;
  expected_reason_code: string;
  expected_effect: string;
  actual_decision: string;
  actual_reason_code: string | null;
  observed_effects: Record<string, boolean>;
  side_effect: boolean;
  error: string | null;
  decision_correct: boolean;
  completed: boolean;
};

export type ClassifierPrediction = {
  model_version: string;
  policy_version: string;
  prediction: "allow" | "approval" | "ambiguous" | "deny";
  decision_hint: string;
  confidence: number;
  margin: number;
  abstained: boolean;
  reason: string | null;
  probabilities: Record<string, number>;
  threshold: number;
  margin_threshold: number;
  authority: string;
};

export type ClassifierMetrics = {
  dataset_version: string;
  dataset_source: string;
  dataset_size: number;
  train_size: number;
  test_size: number;
  split: string;
  evaluation_scope: string;
  labels: string[];
  accuracy: number;
  accuracy_definition: string;
  exact_match_accuracy: number;
  macro_f1: number | null;
  macro_f1_note: string;
  per_class: Record<
    string,
    {
      support: number;
      tp: number;
      fp: number;
      fn: number;
      precision: number | null;
      recall: number | null;
      f1: number | null;
    }
  >;
  confusion_matrix: Record<string, Record<string, number>>;
  abstentions: number;
  abstention_rate: number;
  false_positive: number;
  false_negative: number;
  false_positive_definition: string;
  false_negative_definition: string;
  thresholds: { confidence: number; margin: number; oov_ratio: number };
  feature_count: number;
  model_version: string;
  policy_version: string;
};

export type ClassifierDoc = {
  model_version: string;
  dataset_version: string;
  dataset_source: string;
  labels: string[];
  thresholds: { confidence: number; margin: number; oov_ratio: number };
  authority: string;
  metrics: ClassifierMetrics;
};

export type SimulationStep = {
  step: number;
  name: string;
  request: Record<string, unknown> & {
    tool_name: string;
    operation: string;
    arguments: Record<string, unknown>;
    session_id: string;
  };
  response: GatewayResponse;
  audit_events: AuditEvent[];
  observed: Record<string, unknown>;
};

export type SimulationResult = {
  run_id: string;
  scenario: string;
  scenario_label: string;
  scenario_description: string;
  created_at: number;
  policy_version: string;
  actor_id: string;
  session_id: string;
  steps: SimulationStep[];
  result: {
    request_id: string;
    decision: Decision | null;
    reason_code: string | null;
    status: string | null;
    explanation: string | null;
    executed: boolean;
    side_effect: boolean;
    blocked_at: string | null;
    approval_id: string | null;
    outbox_before: number;
    outbox_after: number;
    execution_rows: number;
  };
  audit: { event_count: number; head: string };
  notes: string[];
};

export type SimulationSummary = {
  run_id: string;
  scenario: string;
  created_at: number;
  outcome: string;
  reason_code: string | null;
};

export type Metrics = {
  generated_at: number;
  policy_version: string;
  tool_calls: number;
  decisions: { ALLOW: number; DENY: number; APPROVAL: number };
  executions: number;
  unauthorized_executions: number;
  pending_approvals: number;
  approvals: number;
  audit: { valid: boolean; event_count: number; head: string; failures: string[] };
  simulations: { count: number; latest: SimulationSummary | null };
  classifier: {
    model_version: string;
    dataset_version: string;
    dataset_size: number;
    test_size: number;
    accuracy: number;
    macro_f1: number | null;
    abstention_rate: number;
    false_positive: number;
    false_negative: number;
    authority: string;
  };
  sources: Record<string, string>;
};

export type EvaluationResults = {
  run_id: string;
  created_at: number;
  fixture_count: number;
  fixture_provenance: string;
  conditions: Record<"firewall_off" | "firewall_on", { description: string; cases: EvalCase[] }>;
  metrics: Record<string, Metric | { firewall_off: Metric; firewall_on: Metric }>;
  experiments: Record<string, unknown>;
  notes: string[];
};
