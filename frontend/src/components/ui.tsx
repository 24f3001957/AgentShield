import { useState, type ReactNode } from "react";
import { copyText, shortHash } from "../lib/format";
import type { Decision } from "../lib/types";

export type Tone = "teal" | "blue" | "amber" | "coral" | "purple" | "muted";

export function Badge({
  tone = "muted",
  children,
  title,
}: {
  tone?: Tone;
  children: ReactNode;
  title?: string;
}) {
  return (
    <span className={`badge badge--${tone}`} title={title}>
      {children}
    </span>
  );
}

export function decisionTone(decision: Decision | string | null | undefined): Tone {
  switch (decision) {
    case "ALLOW":
      return "teal";
    case "APPROVAL":
      return "amber";
    case "DENY":
      return "coral";
    default:
      return "muted";
  }
}

export function stateTone(state: string | null | undefined): Tone {
  switch (state) {
    case "EXECUTED":
    case "APPROVED":
    case "EXECUTING":
      return "teal";
    case "AWAITING_APPROVAL":
    case "PENDING_APPROVAL":
    case "REVALIDATED":
    case "CONSUMED":
      return "amber";
    case "DENIED":
    case "REJECTED":
    case "FAILED":
    case "AUDIT_FAILURE":
    case "NO_EXECUTION":
    case "EXPIRED":
      return "coral";
    default:
      return "muted";
  }
}

export function DecisionBadge({ decision }: { decision: Decision | string | null }) {
  if (!decision) return <Badge tone="muted">—</Badge>;
  const label =
    decision === "APPROVAL" ? "APPROVAL" : decision === "ALLOW" ? "ALLOW" : decision;
  return <Badge tone={decisionTone(decision)}>{label}</Badge>;
}

export function StateBadge({ state }: { state: string | null | undefined }) {
  if (!state) return <Badge tone="muted">no state</Badge>;
  return <Badge tone={stateTone(state)}>{state.replaceAll("_", " ")}</Badge>;
}

export function PageHeader({
  eyebrow,
  title,
  subtitle,
  actions,
}: {
  eyebrow?: string;
  title: string;
  subtitle?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div>
        {eyebrow ? <p className="page-eyebrow">{eyebrow}</p> : null}
        <h1 className="page-title">{title}</h1>
        {subtitle ? <p className="page-subtitle">{subtitle}</p> : null}
      </div>
      {actions ? <div className="page-actions">{actions}</div> : null}
    </header>
  );
}

export function Panel({
  title,
  subtitle,
  actions,
  children,
  className = "",
  padded = true,
}: {
  title?: string;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  padded?: boolean;
}) {
  return (
    <section className={`panel ${className}`}>
      {title || actions ? (
        <div className="panel-head">
          <div>
            {title ? <h2 className="panel-title">{title}</h2> : null}
            {subtitle ? <p className="panel-subtitle">{subtitle}</p> : null}
          </div>
          {actions ? <div className="panel-actions">{actions}</div> : null}
        </div>
      ) : null}
      <div className={padded ? "panel-body" : "panel-body panel-body--flush"}>{children}</div>
    </section>
  );
}

export function StatCard({
  label,
  value,
  hint,
  tone = "muted",
  onClick,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: Tone;
  onClick?: () => void;
}) {
  const content = (
    <>
      <span className="stat-label">{label}</span>
      <span className={`stat-value stat-value--${tone}`}>{value}</span>
      {hint ? <span className="stat-hint">{hint}</span> : null}
    </>
  );
  if (onClick) {
    return (
      <button type="button" className="stat-card stat-card--clickable" onClick={onClick}>
        {content}
      </button>
    );
  }
  return <div className="stat-card">{content}</div>;
}

export function EmptyState({
  title,
  message,
  action,
}: {
  title: string;
  message?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <span className="empty-glyph" aria-hidden="true">
        ◇
      </span>
      <p className="empty-title">{title}</p>
      {message ? <p className="empty-message">{message}</p> : null}
      {action ? <div className="empty-action">{action}</div> : null}
    </div>
  );
}

export function ErrorBanner({ error, onRetry }: { error: string; onRetry?: () => void }) {
  return (
    <div className="error-banner" role="alert">
      <span aria-hidden="true">!</span>
      <div>
        <strong>Backend request failed</strong>
        <p>{error}</p>
      </div>
      {onRetry ? (
        <button type="button" className="btn btn--ghost btn--sm" onClick={onRetry}>
          Retry
        </button>
      ) : null}
    </div>
  );
}

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <div className="loading" role="status">
      <span className="loading-dot" aria-hidden="true" />
      <span>{label}…</span>
    </div>
  );
}

export function KeyValue({
  label,
  children,
  mono = false,
}: {
  label: string;
  children: ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="kv">
      <span className="kv-label">{label}</span>
      <span className={`kv-value${mono ? " mono" : ""}`}>{children}</span>
    </div>
  );
}

export function JsonBlock({ value, maxHeight }: { value: unknown; maxHeight?: number }) {
  return (
    <pre className="json-block" style={maxHeight ? { maxHeight } : undefined}>
      {typeof value === "string" ? value : JSON.stringify(value, null, 2)}
    </pre>
  );
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="btn btn--ghost btn--xs"
      onClick={async () => {
        const ok = await copyText(value);
        setCopied(ok);
        window.setTimeout(() => setCopied(false), 1400);
      }}
    >
      {copied ? "Copied" : label}
    </button>
  );
}

export function Hash({ value }: { value: string | null | undefined }) {
  if (!value) return <span className="mono">—</span>;
  return (
    <span className="hash">
      <code className="mono" title={value}>
        {shortHash(value)}
      </code>
      <CopyButton value={value} label="Copy" />
    </span>
  );
}

export function RefreshNote({ updatedAt }: { updatedAt: number | null }) {
  if (!updatedAt) return null;
  return (
    <span className="refresh-note">
      refreshed {new Date(updatedAt).toLocaleTimeString(undefined, { hour12: false })}
    </span>
  );
}
