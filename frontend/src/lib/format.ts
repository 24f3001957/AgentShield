export function messageOf(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

export function relativeTime(epochSeconds: number | null | undefined, now = Date.now()): string {
  if (!epochSeconds) return "—";
  const delta = Math.round(now / 1000 - epochSeconds);
  if (delta < 5) return "just now";
  if (delta < 60) return `${delta}s ago`;
  if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
  if (delta < 86400) return `${Math.floor(delta / 3600)}h ago`;
  return `${Math.floor(delta / 86400)}d ago`;
}

export function untilTime(epochSeconds: number | null | undefined, now = Date.now()): string {
  if (!epochSeconds) return "—";
  const delta = Math.round(epochSeconds - now / 1000);
  if (delta <= 0) return "expired";
  if (delta < 60) return `${delta}s left`;
  if (delta < 3600) return `${Math.floor(delta / 60)}m left`;
  return `${Math.floor(delta / 3600)}h left`;
}

export function formatTimestamp(value: string | number | null | undefined): string {
  if (value === null || value === undefined || value === "") return "—";
  const date = typeof value === "number" ? new Date(value * 1000) : new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZoneName: "short",
  });
}

export function formatClock(value: string | number | null | undefined): string {
  if (value === null || value === undefined || value === "") return "—";
  const date = typeof value === "number" ? new Date(value * 1000) : new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function timezoneLabel(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "local time";
  } catch {
    return "local time";
  }
}

export function shortHash(hash: string | null | undefined, length = 12): string {
  if (!hash) return "—";
  if (hash.length <= length * 2 + 1) return hash;
  return `${hash.slice(0, length)}…${hash.slice(-4)}`;
}

export function formatRate(rate: number | string): string {
  if (typeof rate === "string") return rate;
  return `${(rate * 100).toFixed(1)}%`;
}

export function pluralize(count: number, singular: string, plural = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : plural}`;
}

export function downloadJson(filename: string, data: unknown): void {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export async function copyText(value: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(value);
    return true;
  } catch {
    return false;
  }
}
