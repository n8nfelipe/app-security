import { NavLink, Route, Routes } from "react-router-dom";

import { ExportPanel } from "./components/ExportPanel";
import { ThemeToggle } from "./components/ThemeToggle";
import { OverviewPage } from "./pages/OverviewPage";
import { SecurityPage } from "./pages/SecurityPage";
import { PerformancePage } from "./pages/PerformancePage";
import { RecommendationsPage } from "./pages/RecommendationsPage";
import { HistoryPage } from "./pages/HistoryPage";
import { useAuditData } from "./lib/useAuditData";
import { useTheme } from "./lib/useTheme";

const navItems = [
  { to: "/", label: "Visao geral" },
  { to: "/security", label: "Seguranca" },
  { to: "/performance", label: "Performance" },
  { to: "/recommendations", label: "Recomendacoes" },
  { to: "/history", label: "Historico" },
];

export default function App() {
  const audit = useAuditData();
  const { theme, toggleTheme } = useTheme();

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <p className="eyebrow">App Security</p>
          <h1>Linux Security Console</h1>
          <p className="muted">
            Coleta read-only para hardening, capacidade e plano de acao.
          </p>
        </div>
        <div className="status-block">
          <span className="status-dot" />
          <div>
            <strong>{audit.result?.machine_hostname ?? "host local"}</strong>
            <p className="muted">Modo {audit.result?.mode ?? "agentless"} com leitura defensiva.</p>
          </div>
        </div>
        <ThemeToggle theme={theme} onToggle={toggleTheme} />
        <nav className="nav">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <button className="primary-button" onClick={audit.startScan} disabled={audit.loading}>
          {audit.loading ? "Coletando..." : "Nova coleta"}
        </button>
        <ExportPanel onExportJson={audit.exportJson} onExportPdf={audit.exportPdf} disabled={!audit.result} />
      </aside>

      <main className="content">
        {audit.error ? <div className="banner error">{audit.error}</div> : null}
        {audit.notice ? <div className="banner">{audit.notice}</div> : null}
        <Routes>
          <Route path="/" element={<OverviewPage audit={audit} />} />
          <Route path="/security" element={<SecurityPage audit={audit} />} />
          <Route path="/performance" element={<PerformancePage audit={audit} />} />
          <Route path="/recommendations" element={<RecommendationsPage audit={audit} />} />
          <Route path="/history" element={<HistoryPage audit={audit} />} />
        </Routes>
      </main>
    </div>
  );
}
