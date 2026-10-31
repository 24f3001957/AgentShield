import { requestIdOf, sessionIdOf } from "./events";
import type { AuditEvent } from "./types";

export type Chain = {
  /** Stable id: request id, or "system" for events without a request. */
  id: string;
  requestId: string | null;
  session: string;
  events: AuditEvent[];
};

const SYSTEM = "system";

/**
 * Build trace chains from the authoritative audit record.
 *
 * Session is only ever taken from recorded events (tool_call_received /
 * provenance_recorded); nothing is inferred from agent intent. Events that
 * carry no request id (integrity checks) form a system chain.
 */
export function groupChains(events: AuditEvent[]): { chains: Chain[]; sessions: string[] } {
  const requestSession = new Map<string, string>();
  for (const event of events) {
    const requestId = requestIdOf(event);
    const session = sessionIdOf(event);
    if (requestId && session && !requestSession.has(requestId)) {
      requestSession.set(requestId, session);
    }
  }

  const byChain = new Map<string, AuditEvent[]>();
  for (const event of events) {
    const id = requestIdOf(event) ?? SYSTEM;
    const bucket = byChain.get(id);
    if (bucket) bucket.push(event);
    else byChain.set(id, [event]);
  }

  const chains: Chain[] = [];
  for (const [id, items] of byChain) {
    items.sort((a, b) => a.seq - b.seq);
    const requestId = id === SYSTEM ? null : id;
    const session =
      (requestId ? requestSession.get(requestId) : undefined) ??
      (requestId ? "unassigned session" : SYSTEM);
    chains.push({ id, requestId, session, events: items });
  }

  chains.sort((a, b) => (a.events[0]?.seq ?? 0) - (b.events[0]?.seq ?? 0));

  const sessions = [...new Set(chains.map((chain) => chain.session))].sort();
  return { chains, sessions };
}

export function eventMatches(event: AuditEvent, query: string, decision: string): boolean {
  if (decision !== "all") {
    if (event.event_type === "policy_decision") {
      const value = event.payload.decision;
      if (value !== decision) return false;
    } else if (decision === "DENY" && event.event_type !== "policy_decision") {
      // Denials are only evidenced by the policy decision node; other events
      // in the chain stay visible but are not counted as a match.
      return false;
    } else if (decision === "ALLOW" || decision === "APPROVAL") {
      return false;
    }
  }
  if (!query.trim()) return true;
  const needle = query.trim().toLowerCase();
  return [
    event.event_type,
    String(event.seq),
    event.event_hash,
    JSON.stringify(event.payload),
  ]
    .join(" ")
    .toLowerCase()
    .includes(needle);
}
