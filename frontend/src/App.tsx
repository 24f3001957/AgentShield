import { Route, Routes } from "react-router-dom";
import { PlasmaBackground } from "./components/PlasmaBackground";
import { Shell } from "./components/Shell";
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
    <div className="app relative isolate">
      <PlasmaBackground />
      <div className="plasma-scrim absolute inset-0 -z-10 pointer-events-none" aria-hidden="true" />
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
    </div>
  );
}
