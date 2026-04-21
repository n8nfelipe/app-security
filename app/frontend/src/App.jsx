import { NavLink, Route, Routes } from "react-router-dom";

import { ExportPanel } from "./components/ExportPanel";
import { ThemeToggle } from "./components/ThemeToggle";
import { OverviewPage } from "./pages/OverviewPage";
import { SecurityPage } from "./pages/SecurityPage";
import { PerformancePage } from "./pages/PerformancePage";
import { RecommendationsPage } from "./pages/RecommendationsPage";
import { HistoryPage } from "./pages/HistoryPage";
import { NetworkPage } from "./pages/NetworkPage";
import { useAuditData } from "./lib/useAuditData";
import { useTheme } from "./lib/useTheme";
import { ContainersPage } from "./pages/ContainersPage";
import { NetworkDevicesPage } from "./pages/NetworkDevicesPage";
import { UsersPage } from "./pages/UsersPage";
import { RulesPage } from "./pages/RulesPage";

const navItems = [
  { to: "/", label: "Visao geral" },
  { to: "/usuarios", label: "Usuarios" },
  { to: "/regras", label: "Regras" },
  { to: "/containers", label: "Containers" },
  { to: "/network-devices", label: "Dispositivos" },
  { to: "/security", label: "Seguranca" },
  { to: "/performance", label: "Performance" },
  { to: "/network", label: "Rede" },
  { to: "/recommendations", label: "Recomendacoes" },
  { to: "/history", label: "Historico" },
];

export default function App() {
  const audit = useAuditData();
  const { theme, toggleTheme } = useTheme();
  const headlineStats = [
    { label: "Score", value: audit.result?.scores?.overall ?? "--" },
    { label: "Findings", value: audit.result?.findings?.length ?? 0 },
    { label: "Plano", value: audit.result?.recommendations?.length ?? 0 },
  ];

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand brand-panel">
          <div className="brand-mark" />
          <div>
            <p className="eyebrow">App Security</p>
            <h1>Linux Security Console</h1>
            <p className="muted">
              Coleta read-only para hardening, capacidade e plano de acao.
            </p>
          </div>
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
        <section className="top-ribbon reveal">
          <div className="ribbon-copy">
            <span className="eyebrow">Control Room</span>
            <strong>Postura do host, sinais de risco e trilha de remediacao em uma unica superficie.</strong>
          </div>
          <div className="ribbon-stats">
            {headlineStats.map((item) => (
              <div className="ribbon-pill" key={item.label}>
                <span>{item.label}</span>
                <strong>{item.value}</strong>
              </div>
            ))}
          </div>
        </section>
        {audit.error ? <div className="banner error">{audit.error}</div> : null}
        {audit.notice ? <div className="banner">{audit.notice}</div> : null}
         <Routes>
<Route path="/" element={<OverviewPage audit={audit} />} />
            <Route path="/usuarios" element={<UsersPage />} />
            <Route path="/regras" element={<RulesPage />} />
            <Route path="/containers" element={<ContainersPage />} />
           <Route path="/network-devices" element={<NetworkDevicesPage />} />
           <Route path="/security" element={<SecurityPage audit={audit} />} />
           <Route path="/performance" element={<PerformancePage audit={audit} />} />
           <Route path="/network" element={<NetworkPage audit={audit} />} />
           <Route path="/recommendations" element={<RecommendationsPage audit={audit} />} />
           <Route path="/history" element={<HistoryPage audit={audit} />} />
         </Routes>
      </main>
    </div>
  );
}
