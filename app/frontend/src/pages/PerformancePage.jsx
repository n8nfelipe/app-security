import { FindingsTable } from "../components/FindingsTable";
import { ProcessChart } from "../components/ProcessChart";
import { ScoreTrendChart } from "../components/ScoreTrendChart";

export function PerformancePage({ audit }) {
  const summary = audit.result?.summary;
  return (
    <div className="page">
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
