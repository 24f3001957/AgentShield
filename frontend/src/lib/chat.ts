/**
 * Deterministic intent mapping for the embedded assistant.
 *
 * The parser produces one of a fixed set of intents; nothing here can name an
 * arbitrary endpoint. Execution lives in `ChatDock`, which calls the allowlisted
 * API methods only, and every state-changing intent still goes through an
 * explicit confirmation step and the backend gateway.
 */
export type ChatIntent =
  | { kind: "run_simulation" }
  | { kind: "pending_approvals" }
  | { kind: "approve"; approvalId: string | null }
  | { kind: "reject"; approvalId: string | null }
  | { kind: "verify_audit" }
  | { kind: "compare" }
  | { kind: "latest" }
  | { kind: "help" }
  | { kind: "unknown"; input: string };

export const CHAT_COMMANDS = [
  "Run the secret-read attack",
  "Show pending approvals",
  "Approve this request",
  "Reject this request",
  "Verify the audit log",
  "Compare firewall on and off",
  "Show the latest simulation results",
] as const;

const APPROVAL_ID = /(apr_[0-9a-f]{6,})/i;

function has(text: string, ...words: string[]): boolean {
  return words.some((word) => text.includes(word));
}

export function parseIntent(raw: string): ChatIntent {
  const text = raw.trim().toLowerCase();
  if (!text) return { kind: "unknown", input: raw };

  const approvalId = text.match(APPROVAL_ID)?.[1] ?? null;

  if (has(text, "reject", "decline", "deny this approval")) {
    return { kind: "reject", approvalId };
  }
  if (has(text, "approve", "approval for", "accept this request")) {
    return { kind: "approve", approvalId };
  }
  if (has(text, "verify", "integrity", "tamper", "chain")) {
    return { kind: "verify_audit" };
  }
  if (has(text, "compare", "firewall off", "firewall on", "evaluation", "benchmark")) {
    return { kind: "compare" };
  }
  if (has(text, "pending approval", "pending approvals", "show approvals", "approval queue", "waiting")) {
    return { kind: "pending_approvals" };
  }
  if (has(text, "latest simulation", "last simulation", "latest run", "latest results", "latest attack")) {
    return { kind: "latest" };
  }
  if (
    has(
      text,
      "secret-read",
      "secret read",
      "exfiltration",
      "exfiltrate",
      "run the attack",
      "run attack",
      "simulate",
      "simulation",
      "attack",
    )
  ) {
    return { kind: "run_simulation" };
  }
  if (has(text, "help", "commands", "what can you")) {
    return { kind: "help" };
  }
  return { kind: "unknown", input: raw };
}
