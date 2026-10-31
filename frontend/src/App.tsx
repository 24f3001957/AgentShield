import { Route, Routes } from "react-router-dom";
import GradientASCII from "./components/GradientASCII";
import { ChatDock } from "./components/ChatDock";
import { Shell } from "./components/Shell";
import { AppStateProvider } from "./lib/appState";
import AccessControl from "./pages/AccessControl";
import Approvals from "./pages/Approvals";
import AuditLogs from "./pages/AuditLogs";
import Console from "./pages/Console";
import Dashboard from "./pages/Dashboard";
import Evaluation from "./pages/Evaluation";
import ExecutionGraph from "./pages/ExecutionGraph";
import Integrity from "./pages/Integrity";
import NotFound from "./pages/NotFound";

export default function App() {
  return (
    <AppStateProvider>
      <div className="app relative isolate">
        <GradientASCII
          colors={["#1e3fd8", "#f6f8ff", "#a5d8ff", "#38bdf8"]}
          shape="horizon"
          characters=" =+xX0S8#@"
          cellSize={18}
          density={0.55}
          glyphOpacity={0.3}
          glow={0.18}
          depthOfField={0.35}
          flicker={0.18}
          softness={0.55}
          scale={1}
          flow={0.5}
          speed={0.6}
          gradientOpacity={0.32}
          grain={0.1}
          variation={0.12}
          mouseInteraction
          scrambleRadius={0.08}
          clickEffect="wave"
          intro
          lightMode={false}
        />
        <div className="plasma-scrim" aria-hidden="true" />
        <Shell>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/graph" element={<ExecutionGraph />} />
            <Route path="/logs" element={<AuditLogs />} />
            <Route path="/approvals" element={<Approvals />} />
            <Route path="/access" element={<AccessControl />} />
            <Route path="/integrity" element={<Integrity />} />
            <Route path="/evaluation" element={<Evaluation />} />
            <Route path="/console" element={<Console />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </Shell>
        <ChatDock />
      </div>
    </AppStateProvider>
  );
}
