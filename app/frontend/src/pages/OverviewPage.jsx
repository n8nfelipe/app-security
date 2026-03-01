import { FindingsTable } from "../components/FindingsTable";
import { ProcessChart } from "../components/ProcessChart";
import { ScoreCards } from "../components/ScoreCards";
import { ScoreTrendChart } from "../components/ScoreTrendChart";
import { SeverityChart } from "../components/SeverityChart";

export function OverviewPage({ audit }) {
  const summary = audit.result?.summary;
  return (
    <div className="page">
      <header className="hero">
        <div>
          <p className="eyebrow">Painel operacional</p>
          <h2>Seguranca e performance do host Linux em uma trilha unica.</h2>
        </div>
        <div className="hero-meta">
          <span>Host: {audit.result?.machine_hostname ?? "sem coleta"}</span>
          <span>Distro: {audit.result?.distro ?? "n/a"}</span>
        </div>
      </header>
      <ScoreCards scores={audit.result?.scores} />
      <section className="analytics-grid">
        <ScoreTrendChart scores={audit.result?.scores} />
        <SeverityChart findings={audit.result?.findings ?? []} />
      </section>
      <section className="summary-grid">
        <article className="panel">
          <h2>Resumo executivo</h2>
          <div className="metric-grid">
            <div className="metric-tile">
              <span>Usuarios humanos</span>
              <strong>{summary?.human_users ?? "--"}</strong>
            </div>
            <div className="metric-tile">
              <span>Portas em escuta</span>
              <strong>{summary?.listening_ports ?? "--"}</strong>
            </div>
            <div className="metric-tile">
              <span>Findings criticos</span>
              <strong>{summary?.critical_findings ?? "--"}</strong>
            </div>
          </div>
        </article>
        <ProcessChart processes={summary?.top_processes ?? []} />
      </section>
      <FindingsTable findings={audit.result?.findings ?? []} />
    </div>
  );
}
