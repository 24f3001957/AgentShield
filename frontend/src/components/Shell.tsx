import { useEffect, useState, type ReactNode } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { api } from "../lib/api";
import { timezoneLabel } from "../lib/format";
import type { Health } from "../lib/types";

const NAV = [
  { to: "/", label: "Dashboard", icon: "grid", end: true },
  { to: "/graph", label: "Execution Graph", icon: "graph" },
  { to: "/logs", label: "Audit Logs", icon: "list" },
  { to: "/approvals", label: "Approvals", icon: "shield" },
  { to: "/access", label: "Access Control", icon: "key" },
  { to: "/integrity", label: "Integrity", icon: "link" },
  { to: "/evaluation", label: "Evaluation", icon: "chart" },
  { to: "/console", label: "Agent Console", icon: "terminal" },
];

function Icon({ name }: { name: string }) {
  const paths: Record<string, string> = {
    grid: "M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z",
    graph: "M5 6h4v4H5zM15 4h4v4h-4zM15 16h4v4h-4zM9 8h6M17 8v8M9 8v8h6",
    list: "M4 6h16M4 12h16M4 18h10",
    shield: "M12 3l7 3v5c0 4-3 7-7 9-4-2-7-5-7-9V6zM9 12l2 2 4-4",
    key: "M14 10a4 4 0 1 1-3-3.9M14 10l6 6M17 13l2-2M20 16l1.5-1.5",
    link: "M9 15l6-6M7.5 12.5l-2 2a3.5 3.5 0 1 0 5 5l2-2M16.5 11.5l2-2a3.5 3.5 0 1 0-5-5l-2 2",
    chart: "M4 20V10M10 20V4M16 20v-7M22 20H2",
    terminal: "M4 5h16v14H4zM7 10l3 2-3 2M12 15h5",
  };
  return (
    <svg
      className="nav-icon"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={paths[name] ?? paths.grid} />
    </svg>
  );
}

function useConnection() {
  const [health, setHealth] = useState<Health | null>(null);
  const [offline, setOffline] = useState(false);
  useEffect(() => {
    let alive = true;
    let timer: number | undefined;
    const tick = async () => {
      try {
        const next = await api.health();
        if (!alive) return;
        setHealth(next);
        setOffline(false);
      } catch {
        if (!alive) return;
        setOffline(true);
      }
      if (alive) timer = window.setTimeout(tick, 5000);
    };
    void tick();
    return () => {
      alive = false;
      if (timer) window.clearTimeout(timer);
    };
  }, []);
  return { health, offline };
}

export function Shell({ children }: { children: ReactNode }) {
  const { health, offline } = useConnection();
  const location = useLocation();

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            ◈
          </span>
          <span>
            <span className="brand-name">AGENTSHIELD</span>
            <span className="brand-sub">CB-05 · permission firewall</span>
          </span>
        </div>

        <nav className="nav" aria-label="Primary">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) => `nav-link${isActive ? " nav-link--active" : ""}`}
            >
              <Icon name={item.icon} />
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-foot">
          <p className="sidebar-note">
            Mock tools only. No real files, mail or network side effects are reachable
            from this console.
          </p>
          <p className="sidebar-note sidebar-note--dim">
            The UI is not a security boundary; every decision and authorization is issued
            by the backend gateway.
          </p>
        </div>
      </aside>

      <div className="workspace">
        <header className="topbar">
          <div className="topbar-status">
            <span
              className={`status-pill status-pill--${offline ? "offline" : "online"}`}
              title={offline ? "The FastAPI backend is not responding" : "Backend reachable"}
            >
              <span className="status-dot" aria-hidden="true" />
              {offline ? "Backend unavailable" : "Backend connected"}
            </span>
            <span className="mode-chip">{offline ? "OFFLINE" : "LIVE"}</span>
            <span className="topbar-context">{navTitle(location.pathname)}</span>
          </div>
          <div className="topbar-meta">
            <span className="meta-item">
              policy <code className="mono">{health?.policy_version ?? "—"}</code>
            </span>
            <span className="meta-item">
              audit events <code className="mono">{health?.audit_events ?? "—"}</code>
            </span>
            <span className="meta-item">{timezoneLabel()}</span>
          </div>
        </header>
        <main className="content">{children}</main>
      </div>
    </div>
  );
}

function navTitle(pathname: string): string {
  const item = NAV.find((entry) =>
    entry.end ? pathname === entry.to : pathname.startsWith(entry.to),
  );
  return item ? item.label : "Console";
}
