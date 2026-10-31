import type { AuditEvent } from "./types";

export type Tone = "teal" | "blue" | "amber" | "coral" | "purple" | "muted";

export type EventMeta = {
  kind: string;
  label: string;
  tone: Tone;
  glyph: string;
};

function text(value: unknown): string | null {
  return typeof value === "string" && value ? value : null;
}

/** Visual + textual taxonomy for every event the backend can emit. */
export function metaFor(event: AuditEvent): EventMeta {
  const { event_type: type, payload } = event;
  switch (type) {
    case "tool_call_received":
      return { kind: "proposal", label: "Tool call proposed", tone: "blue", glyph: "▸" };
    case "validation_failed":
      return { kind: "validation", label: "Validation failed", tone: "coral", glyph: "!" };
    case "policy_decision": {
      const decision = text(payload.decision);
      if (decision === "ALLOW") {
        return { kind: "decision", label: "Allowed by policy", tone: "teal", glyph: "✓" };
      }
      if (decision === "APPROVAL") {
        return { kind: "decision", label: "Approval required", tone: "amber", glyph: "◷" };
      }
      if (decision === "DENY") {
        return { kind: "decision", label: "Denied by policy", tone: "coral", glyph: "✕" };
      }
      return { kind: "decision", label: "Policy decision", tone: "muted", glyph: "◇" };
    }
    case "approval_created":
      return { kind: "approval", label: "Approval requested", tone: "amber", glyph: "◷" };
    case "approval_decided": {
      const decision = text(payload.decision);
      if (decision === "REJECT") {
        return { kind: "approval", label: "Rejected by reviewer", tone: "coral", glyph: "✕" };
      }
      return { kind: "approval", label: "Approved by reviewer", tone: "teal", glyph: "✓" };
    }
    case "approval_revalidated":
      return { kind: "approval", label: "Approval revalidated", tone: "amber", glyph: "⟳" };
    case "approval_consumed":
      return { kind: "approval", label: "Approval consumed", tone: "amber", glyph: "◧" };
    case "approval_rejected":
      return { kind: "approval", label: "Approval refused", tone: "coral", glyph: "✕" };
    case "authorization_issued":
      return { kind: "authorization", label: "Authorization issued", tone: "blue", glyph: "⌘" };
    case "authorization_rejected":
      return { kind: "authorization", label: "Authorization rejected", tone: "coral", glyph: "✕" };
    case "execution_requested":
      return { kind: "execution", label: "Execution requested", tone: "blue", glyph: "▸" };
    case "execution_started":
      return { kind: "execution", label: "Execution started", tone: "blue", glyph: "◐" };
    case "execution_completed":
    case "execution_recorded":
      return { kind: "execution", label: "Execution recorded", tone: "teal", glyph: "✓" };
    case "execution_failed":
      return { kind: "execution", label: "Execution failed", tone: "coral", glyph: "!" };
    case "provenance_recorded":
      return { kind: "resource", label: "Provenance recorded", tone: "teal", glyph: "❖" };
    case "audit_verification":
      return { kind: "integrity", label: "Integrity check", tone: "purple", glyph: "⛓" };
    default:
      return { kind: "system", label: type.replaceAll("_", " "), tone: "muted", glyph: "•" };
  }
}

export function requestIdOf(event: AuditEvent): string | null {
  return text(event.payload.request_id);
}

export function sessionIdOf(event: AuditEvent): string | null {
  return text(event.payload.session_id);
}

export function decisionOf(event: AuditEvent): string | null {
  return text(event.payload.decision);
}

export function toolOf(event: AuditEvent): string | null {
  return text(event.payload.tool_name);
}

/** Free-text search across the fields a reviewer actually searches by. */
export function matchesQuery(event: AuditEvent, query: string): boolean {
  if (!query.trim()) return true;
  const needle = query.trim().toLowerCase();
  const haystack = [
    event.event_type,
    String(event.seq),
    event.event_hash,
    event.prev_hash,
    ...Object.values(event.payload).map((value) =>
      typeof value === "object" && value !== null
        ? JSON.stringify(value)
        : String(value ?? ""),
    ),
  ]
    .join(" ")
    .toLowerCase();
  return haystack.includes(needle);
}
