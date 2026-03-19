import { FindingsTable } from "../components/FindingsTable";
import { ProcessChart } from "../components/ProcessChart";
import { ScoreTrendChart } from "../components/ScoreTrendChart";

export function PerformancePage({ audit }) {
  const summary = audit.result?.summary;
  const performanceFindings = (audit.result?.findings ?? []).filter((item) => item.domain === "performance");
  return (
    <div className="page">
      <section className="section-shell">
        <div className="section-copy">
          <p className="eyebrow">Performance Lens</p>
          <h2>Capacidade, saturacao e estabilidade vistas como sistema, nao como numeros isolados.</h2>
          <p className="muted">A trilha abaixo combina capacidade, pressao operacional e gargalos visiveis.</p>
        </div>
        <div className="section-metrics">
          <div className="section-metric">
            <span>Score</span>
            <strong>{audit.result?.scores?.performance ?? "--"}</strong>
          </div>
          <div className="section-metric">
            <span>Achados</span>
            <strong>{performanceFindings.length}</strong>
          </div>
        </div>
      </section>
      <section className="analytics-grid">
        <ScoreTrendChart
          rows={[
            { label: "Performance", value: audit.result?.scores?.performance ?? 0, color: "var(--score-performance)" },
            { label: "Capacidade", value: summary?.disk_pressure_mounts?.length ? Math.max(0, 100 - summary.disk_pressure_mounts.length * 10) : 100, color: "var(--score-overall)" },
            { label: "Folga", value: Math.max(0, 100 - (summary?.critical_findings ?? 0) * 8), color: "var(--score-security)" },
          ]}
        />
        <ProcessChart processes={summary?.top_processes ?? []} />
      </section>
      <section className="summary-grid">
        <article className="panel">
          <h2>Score de performance</h2>
          <p className="headline">{audit.result?.scores?.performance ?? "--"}</p>
          <p>Thresholds ficam versionados no backend em arquivo de regras.</p>
        </article>
        <article className="panel">
          <h2>Capacidade</h2>
          {(summary?.disk_pressure_mounts ?? []).length ? (
            summary.disk_pressure_mounts.map((row) => (
              <p key={row.mountpoint}>
                {row.mountpoint}: {row.use_percent}%
              </p>
            ))
          ) : (
            <p>Sem mounts pressionados acima de 85%.</p>
          )}
        </article>
      </section>
      <FindingsTable findings={audit.result?.findings ?? []} domain="performance" />
    </div>
  );
}
