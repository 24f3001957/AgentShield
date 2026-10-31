import type {
  Approval,
  AuditEvent,
  EvaluationResults,
  GatewayResponse,
  Health,
  PolicyDoc,
  ToolCallDetail,
  ToolCallSummary,
  VerifyResult,
} from "./types";

// Dev: the Vite proxy rewrites /api/* to the FastAPI service.
// Build: FastAPI serves this SPA and the API from the same origin.
const BASE: string =
  (import.meta.env.VITE_API_BASE as string | undefined) ??
  (import.meta.env.DEV ? "/api" : "");

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...(init?.body ? { "Content-Type": "application/json" } : {}),
    ...((init?.headers as Record<string, string> | undefined) ?? {}),
  };
  const response = await fetch(`${BASE}${path}`, { ...init, headers });
  const text = await response.text();
  let body: unknown = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
  }
  if (!response.ok) {
    const envelope = body as { error?: { code?: string; detail?: string } } | null;
    const detail =
      envelope?.error?.detail ??
      (typeof body === "string" && body ? body : response.statusText);
    throw new ApiError(
      response.status,
      envelope?.error?.code ?? `http_${response.status}`,
      detail || `request failed (${response.status})`,
    );
  }
  return body as T;
}

function post<T>(path: string, payload?: unknown): Promise<T> {
  return request<T>(path, {
    method: "POST",
    body: payload === undefined ? undefined : JSON.stringify(payload),
  });
}

export function apiBase(): string {
  return BASE;
}

export const api = {
  health: () => request<Health>("/health"),

  policy: () => request<PolicyDoc>("/policy"),

  toolCalls: (limit = 100) =>
    request<{ tool_calls: ToolCallSummary[] }>(`/tool-calls?limit=${limit}`),

  toolCall: (requestId: string) =>
    request<ToolCallDetail>(`/tool-calls/${encodeURIComponent(requestId)}`),

  submit: (payload: Record<string, unknown>) =>
    post<GatewayResponse>("/tool-calls", payload),

  execute: (requestId: string, approvalId: string, body: Record<string, unknown>) =>
    post<GatewayResponse>(
      `/tool-calls/${encodeURIComponent(requestId)}/execute`,
      { approval_id: approvalId, request: body },
    ),

  approvals: (state?: string) =>
    request<{ approvals: Approval[] }>(
      `/approvals${state ? `?state=${encodeURIComponent(state)}` : ""}`,
    ),

  decide: (approvalId: string, approver: string, decision: "APPROVE" | "REJECT") =>
    post<{ approval: Approval; executed: boolean }>(
      `/approvals/${encodeURIComponent(approvalId)}/decision`,
      { approver, decision },
    ),

  auditEvents: (limit = 200) =>
    request<{ events: AuditEvent[]; count: number }>(`/audit/events?limit=${limit}`),

  verify: (options: { expectedCount?: number; expectedHead?: string; record?: boolean } = {}) => {
    const params = new URLSearchParams();
    if (options.expectedCount) params.set("expected_count", String(options.expectedCount));
    if (options.expectedHead) params.set("expected_head", options.expectedHead);
    if (options.record) params.set("record", "true");
    const suffix = params.toString();
    return request<VerifyResult>(`/audit/verify${suffix ? `?${suffix}` : ""}`);
  },

  runEvaluation: () => post<EvaluationResults>("/evaluation/run"),

  evaluationResults: () => request<EvaluationResults>("/evaluation/results"),

  evaluationExportUrl: () => `${BASE}/evaluation/export`,
};

/** Rebuild the exact request an approval is bound to, for re-submission. */
export function requestFromApproval(approval: Approval): Record<string, unknown> {
  const binding = approval.binding;
  return {
    request_id: approval.request_id,
    actor_id: binding.actor_id,
    session_id: binding.session_id,
    tool_name: binding.tool_name,
    operation: binding.operation,
    arguments: binding.arguments,
    resource: binding.resource,
    destination: binding.destination,
    data_classification: binding.data_classification,
    provenance: binding.provenance,
    policy_version: binding.policy_version,
  };
}
