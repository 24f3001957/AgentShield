import { useCallback, useEffect, useRef, useState } from "react";
import { messageOf } from "./format";

type PollState<T> = {
  data: T | null;
  error: string | null;
  updatedAt: number | null;
  loading: boolean;
};

/**
 * Poll an API loader. `intervalMs <= 0` pauses polling (live-follow off);
 * `refresh()` always issues one request and ignores stale responses.
 */
export function usePolled<T>(load: () => Promise<T>, intervalMs = 5000) {
  const [state, setState] = useState<PollState<T>>({
    data: null,
    error: null,
    updatedAt: null,
    loading: true,
  });
  const loadRef = useRef(load);
  loadRef.current = load;
  const sequence = useRef(0);

  const refresh = useCallback(async () => {
    const id = ++sequence.current;
    try {
      const data = await loadRef.current();
      if (id === sequence.current) {
        setState({ data, error: null, updatedAt: Date.now(), loading: false });
      }
    } catch (error) {
      if (id === sequence.current) {
        setState((current) => ({
          ...current,
          error: messageOf(error),
          loading: false,
        }));
      }
    }
  }, []);

  useEffect(() => {
    let alive = true;
    let timer: number | undefined;
    const tick = async () => {
      await refresh();
      if (alive && intervalMs > 0) timer = window.setTimeout(tick, intervalMs);
    };
    void tick();
    return () => {
      alive = false;
      if (timer) window.clearTimeout(timer);
    };
  }, [refresh, intervalMs]);

  return { ...state, refresh };
}

/** Re-render periodically so relative times stay honest. */
export function useNow(intervalMs = 15000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(timer);
  }, [intervalMs]);
  return now;
}
