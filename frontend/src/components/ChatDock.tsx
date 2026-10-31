import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, ApiError } from "../lib/api";
import { useAppState } from "../lib/appState";
import { CHAT_COMMANDS, parseIntent } from "../lib/chat";
import { formatClock, messageOf, pluralize } from "../lib/format";
import type {
  Approval,
  Metric,
  SimulationResult,
  VerifyResult,
} from "../lib/types";
import { Badge, DecisionBadge, Hash } from "./ui";

type Card =
  | { type: "simulation"; run: SimulationResult }
  | { type: "approvals"; items: Approval[] }
  | {
      type: "confirm";
      approvalId: string;
      decision: "APPROVE" | "REJECT";
      label: string;
      target: string;
      expiresAt: number;
    }
  | { type: "audit"; result: VerifyResult }
  | { type: "comparison"; on: Metric; off: Metric; falseBlock: Metric }
  | { type: "error"; message: string };

type Message = {
  id: number;
  role: "user" | "assistant";
  text: string;
  card?: Card;
  at: number;
};

function approvalLabel(approval: Approval): string {
  const binding = approval.binding;
  return `${binding.tool_name}.${binding.operation} → ${
    binding.destination ?? binding.resource ?? "—"
  }`;
}

export function ChatDock() {
  const {
    chatOpen,
    setChatOpen,
    hint,
    clearHint,
    setLatestSimulation,
    bumpData,
    latestSimulation,
  } = useAppState();
  const [messages, setMessages] = useState<Message[]>([
    {
      id: 1,
      role: "assistant",
      text:
        "I can drive the real AgentShield backend: run the secret-read attack, inspect approvals, verify the audit chain, or compare firewall on/off. State-changing actions ask for confirmation first.",
      at: Date.now(),
    },
  ]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const nextId = useRef(2);
  const scroller = useRef<HTMLDivElement | null>(null);
  const handledHint = useRef<string | null>(null);

  useEffect(() => {
    scroller.current?.scrollTo({ top: scroller.current.scrollHeight, behavior: "smooth" });
  }, [messages, chatOpen]);

  function push(message: Omit<Message, "id" | "at">) {
    setMessages((current) => [
      ...current,
      { ...message, id: nextId.current++, at: Date.now() },
    ]);
  }

  async function handle(raw: string) {
    const text = raw.trim();
    if (!text || busy) return;
    push({ role: "user", text });
    setBusy(true);
    const intent = parseIntent(text);
    const say = (message: string, card?: Card) =>
      push({ role: "assistant", text: message, card });

    try {
      switch (intent.kind) {
        case "run_simulation": {
          say("Submitting the secret-read scenario through the gateway…");
          const run = await api.runSecretRead();
          setLatestSimulation(run);
          bumpData();
          say(
            `Gateway verdict: ${run.result.decision ?? "unknown"} (${run.result.reason_code ?? "—"}). ` +
              `${run.result.side_effect ? "A mock side effect occurred." : "No mock side effect occurred."}`,
            { type: "simulation", run },
          );
          break;
        }
        case "pending_approvals": {
          const data = await api.approvals("PENDING_APPROVAL");
          say(
            data.approvals.length === 0
              ? "No action is waiting for a human decision."
              : `${pluralize(data.approvals.length, "action")} waiting for a bound decision.`,
            { type: "approvals", items: data.approvals },
          );
          break;
        }
        case "approve":
        case "reject": {
          const decision = intent.kind === "approve" ? "APPROVE" : "REJECT";
          const all = await api.approvals();
          const pending = all.approvals.filter((item) => item.state === "PENDING_APPROVAL");
          const target = intent.approvalId
            ? all.approvals.find((item) => item.approval_id === intent.approvalId)
            : pending[0];
          if (!target) {
            say(
              intent.approvalId
                ? `No approval with id ${intent.approvalId} exists.`
                : "There is no pending approval to decide.",
            );
            break;
          }
          if (target.state !== "PENDING_APPROVAL") {
            say(
              `Approval ${target.approval_id} is ${target.state}; the backend will refuse a second decision.`,
            );
            break;
          }
          say(
            `Confirm: ${decision === "APPROVE" ? "approve" : "reject"} ${approvalLabel(target)}. ` +
              "Nothing executes on approval; the backend only records the decision.",
            {
              type: "confirm",
              approvalId: target.approval_id,
              decision,
              label: approvalLabel(target),
              target: target.approval_id,
              expiresAt: target.expires_at,
            },
          );
          break;
        }
        case "verify_audit": {
          const result = await api.verify({});
          say(
            result.valid
              ? `Chain verifies over ${pluralize(result.event_count, "event")}. This proves consistency, not completeness.`
              : `Chain verification failed with ${pluralize(result.failures.length, "failure")}.`,
            { type: "audit", result },
          );
          break;
        }
        case "compare": {
          say("Running the paired firewall OFF/ON evaluation — this replays every fixture…");
          const results = await api.runEvaluation();
          bumpData();
          const asr = results.metrics.attack_success_rate as {
            firewall_off: Metric;
            firewall_on: Metric;
          };
          const falseBlock = results.metrics.false_block_rate as {
            firewall_off: Metric;
            firewall_on: Metric;
          };
          say(
            `Attack success rate: OFF ${String(asr.firewall_off.rate)} vs ON ${String(
              asr.firewall_on.rate,
            )}. Fixture suite v${results.fixture_count} cases, run ${results.run_id}.`,
            { type: "comparison", on: asr.firewall_on, off: asr.firewall_off, falseBlock: falseBlock.firewall_on },
          );
          break;
        }
        case "latest": {
          if (latestSimulation) {
            say("The most recent simulation held by this console:", {
              type: "simulation",
              run: latestSimulation,
            });
            break;
          }
          const run = await api.latestSimulation();
          setLatestSimulation(run);
          say("Latest simulation recorded by the backend:", { type: "simulation", run });
          break;
        }
        case "help": {
          say(`Allowlisted commands:\n${CHAT_COMMANDS.map((item) => `• ${item}`).join("\n")}`);
          break;
        }
        default:
          say(
            "I only run a fixed set of backend actions, so I did not execute that. " +
              "Try “Run the secret-read attack”, “Show pending approvals”, or “Verify the audit log”.",
          );
      }
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) {
        say("The backend has no recorded simulation yet. Run the secret-read attack first.");
      } else {
        say("The backend request failed; nothing was changed.", {
          type: "error",
          message: messageOf(error),
        });
      }
    } finally {
      setBusy(false);
    }
  }

  async function confirmDecision(messageId: number, card: Extract<Card, { type: "confirm" }>) {
    if (busy) return;
    setBusy(true);
    try {
      const result = await api.decide(card.approvalId, "sec-lead (console)", card.decision);
      bumpData();
      setMessages((current) =>
        current.map((message) =>
          message.id === messageId ? { ...message, card: undefined } : message,
        ),
      );
      push({
        role: "assistant",
        text:
          `Backend confirmed ${result.approval.state} for ${card.approvalId} by ` +
          `${result.approval.approver}. No tool ran: execution is a separate gateway step.`,
      });
    } catch (error) {
      push({
        role: "assistant",
        text: "The decision was not recorded.",
        card: { type: "error", message: messageOf(error) },
      });
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    if (!chatOpen || !hint || busy) return;
    if (handledHint.current === hint) return;
    handledHint.current = hint;
    clearHint();
    void handle(hint);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [chatOpen, hint]);

  return (
    <>
      <button
        type="button"
        className={`chat-toggle${chatOpen ? " chat-toggle--open" : ""}`}
        aria-expanded={chatOpen}
        aria-controls="assistant-panel"
        onClick={() => setChatOpen(!chatOpen)}
      >
        <span aria-hidden="true">⌘</span>
        <span className="chat-toggle-label">Assistant</span>
      </button>

      {chatOpen ? (
        <aside className="chat-panel" id="assistant-panel" aria-label="AgentShield assistant">
          <header className="chat-head">
            <div>
              <p className="chat-eyebrow">Allowlisted actions</p>
              <h2 className="chat-title">Shield Assistant</h2>
            </div>
            <button
              type="button"
              className="btn btn--ghost btn--xs"
              onClick={() => setChatOpen(false)}
            >
              Close
            </button>
          </header>

          <div className="chat-body" ref={scroller} aria-live="polite">
            {messages.map((message) => (
              <div key={message.id} className={`chat-msg chat-msg--${message.role}`}>
                <div className="chat-bubble">
                  <p className="chat-text">{message.text}</p>
                  {message.card ? (
                    <ChatCard
                      card={message.card}
                      onConfirm={() => {
                        if (message.card?.type === "confirm") {
                          void confirmDecision(message.id, message.card);
                        }
                      }}
                      busy={busy}
                    />
                  ) : null}
                  <time className="chat-time">{formatClock(message.at)}</time>
                </div>
              </div>
            ))}
            {busy ? (
              <div className="chat-msg chat-msg--assistant">
                <div className="chat-bubble chat-bubble--busy" role="status">
                  <span className="loading-dot" aria-hidden="true" /> working through the gateway…
                </div>
              </div>
            ) : null}
          </div>

          <div className="chat-suggestions">
            {CHAT_COMMANDS.slice(0, 4).map((command) => (
              <button
                key={command}
                type="button"
                className="chip"
                disabled={busy}
                onClick={() => void handle(command)}
              >
                {command}
              </button>
            ))}
          </div>

          <form
            className="chat-form"
            onSubmit={(event) => {
              event.preventDefault();
              const text = input;
              setInput("");
              void handle(text);
            }}
          >
            <label className="field-label" htmlFor="chat-input">
              Ask for an action
            </label>
            <div className="chat-input-row">
              <input
                id="chat-input"
                className="input"
                value={input}
                onChange={(event) => setInput(event.target.value)}
                placeholder="Run the secret-read attack"
                autoComplete="off"
                disabled={busy}
              />
              <button type="submit" className="btn btn--primary btn--sm" disabled={busy || !input.trim()}>
                Send
              </button>
            </div>
          </form>

          <p className="chat-footnote">
            Deterministic intent mapping → allowlisted API calls. No generated code, no model-produced
            requests, no client-side authorization.
          </p>
        </aside>
      ) : null}
    </>
  );
}

function ChatCard({
  card,
  onConfirm,
  busy,
}: {
  card: Card;
  onConfirm: () => void;
  busy: boolean;
}) {
  if (card.type === "simulation") {
    const run = card.run;
    const denied = run.result.decision === "DENY";
    return (
      <div className={`chat-card chat-card--${denied ? "deny" : "ok"}`}>
        <div className="chat-card-head">
          <DecisionBadge decision={run.result.decision} />
          <Badge tone={run.result.side_effect ? "coral" : "teal"}>
            {run.result.side_effect ? "side effect" : "no side effect"}
          </Badge>
          <span className="mono muted">{run.result.reason_code ?? "—"}</span>
        </div>
        <p className="chat-card-line">
          {run.steps.length} steps · blocked at <strong>{run.result.blocked_at ?? "none"}</strong> ·
          outbox {run.result.outbox_before} → {run.result.outbox_after}
        </p>
        <p className="chat-card-line muted">
          {run.result.executed
            ? "The executor ran the action — the backend reported a side effect."
            : "The controlled executor was never reached."}
        </p>
        <div className="chat-card-actions">
          <Link className="btn btn--ghost btn--xs" to={`/graph?run=${encodeURIComponent(run.run_id)}`}>
            Animated path
          </Link>
          <Link
            className="btn btn--ghost btn--xs"
            to={`/logs?request=${encodeURIComponent(run.result.request_id)}`}
          >
            Audit events
          </Link>
        </div>
      </div>
    );
  }

  if (card.type === "approvals") {
    return (
      <div className="chat-card">
        <ul className="chat-list">
          {card.items.map((approval) => (
            <li key={approval.approval_id} className="chat-list-item">
              <span className="mono">{approvalLabel(approval)}</span>
              <span className="muted mono">{approval.approval_id}</span>
            </li>
          ))}
        </ul>
        <div className="chat-card-actions">
          <Link className="btn btn--ghost btn--xs" to="/approvals">
            Open approval queue
          </Link>
        </div>
      </div>
    );
  }

  if (card.type === "confirm") {
    return (
      <div className="chat-card chat-card--warn">
        <p className="chat-card-line">
          <strong>{card.decision === "APPROVE" ? "Approve" : "Reject"}</strong> {card.label}
        </p>
        <p className="chat-card-line muted">
          Bound call {" "}
          <span className="mono">{card.target}</span> · expires {formatClock(card.expiresAt * 1000)}.
          This records a decision only; it does not execute the tool.
        </p>
        <div className="chat-card-actions">
          <button
            type="button"
            className={`btn btn--sm ${card.decision === "APPROVE" ? "btn--primary" : "btn--danger"}`}
            onClick={onConfirm}
            disabled={busy}
          >
            Confirm {card.decision === "APPROVE" ? "approval" : "rejection"}
          </button>
        </div>
      </div>
    );
  }

  if (card.type === "audit") {
    return (
      <div className="chat-card">
        <div className="chat-card-head">
          <Badge tone={card.result.valid ? "teal" : "coral"}>
            {card.result.valid ? "VALID" : "FAILED"}
          </Badge>
          <span className="muted">{pluralize(card.result.event_count, "event")}</span>
        </div>
        <div className="kv">
          <span className="kv-label">head</span>
          <Hash value={card.result.head} />
        </div>
        {card.result.failures.length > 0 ? (
          <ul className="failure-list">
            {card.result.failures.map((failure) => (
              <li key={failure}>{failure}</li>
            ))}
          </ul>
        ) : null}
        <div className="chat-card-actions">
          <Link className="btn btn--ghost btn--xs" to="/integrity">
            Open integrity
          </Link>
        </div>
      </div>
    );
  }

  if (card.type === "comparison") {
    return (
      <div className="chat-card">
        <div className="chat-compare">
          <div>
            <span className="stat-label">Firewall OFF</span>
            <span className="stat-value stat-value--coral">{String(card.off.rate)}</span>
            <span className="fine-print">
              {card.off.numerator}/{card.off.denominator} attacks succeeded
            </span>
          </div>
          <div>
            <span className="stat-label">Firewall ON</span>
            <span className="stat-value stat-value--teal">{String(card.on.rate)}</span>
            <span className="fine-print">
              {card.on.numerator}/{card.on.denominator} attacks succeeded
            </span>
          </div>
          <div>
            <span className="stat-label">False blocks</span>
            <span className="stat-value stat-value--purple">{String(card.falseBlock.rate)}</span>
            <span className="fine-print">
              {card.falseBlock.numerator}/{card.falseBlock.denominator} benign tasks
            </span>
          </div>
        </div>
        <div className="chat-card-actions">
          <Link className="btn btn--ghost btn--xs" to="/evaluation">
            Full evaluation
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="chat-card chat-card--error" role="alert">
      <p className="chat-card-line">{card.message}</p>
    </div>
  );
}
