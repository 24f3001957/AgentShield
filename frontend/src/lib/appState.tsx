import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import type { SimulationResult } from "./types";

/**
 * Cross-page state shared by the dashboard, the graph and the chat assistant.
 *
 * Only UI state lives here: every value originates from a backend response and
 * is never treated as authoritative on its own.
 */
type AppState = {
  latestSimulation: SimulationResult | null;
  setLatestSimulation: (run: SimulationResult | null) => void;
  /** Bumped after any state-changing action so pollers refresh immediately. */
  dataVersion: number;
  bumpData: () => void;
  chatOpen: boolean;
  setChatOpen: (open: boolean) => void;
  /** Requested chat action, consumed by the dock when opened from a page. */
  hint: string | null;
  ask: (text: string) => void;
  clearHint: () => void;
};

const AppStateContext = createContext<AppState | null>(null);

export function AppStateProvider({ children }: { children: ReactNode }) {
  const [latestSimulation, setLatestSimulation] = useState<SimulationResult | null>(null);
  const [dataVersion, setDataVersion] = useState(0);
  const [chatOpen, setChatOpen] = useState(false);
  const [hint, setHint] = useState<string | null>(null);

  const bumpData = useCallback(() => setDataVersion((value) => value + 1), []);
  const ask = useCallback((text: string) => {
    setHint(text);
    setChatOpen(true);
  }, []);
  const clearHint = useCallback(() => setHint(null), []);

  const value = useMemo(
    () => ({
      latestSimulation,
      setLatestSimulation,
      dataVersion,
      bumpData,
      chatOpen,
      setChatOpen,
      hint,
      ask,
      clearHint,
    }),
    [latestSimulation, dataVersion, bumpData, chatOpen, hint, ask, clearHint],
  );

  return <AppStateContext.Provider value={value}>{children}</AppStateContext.Provider>;
}

export function useAppState(): AppState {
  const value = useContext(AppStateContext);
  if (!value) throw new Error("useAppState must be used inside AppStateProvider");
  return value;
}
