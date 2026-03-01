import { ChartCard } from "./ChartCard";

export function ProcessChart({ processes }) {
  const maxCpu = Math.max(1, ...(processes ?? []).map((item) => item.cpu_percent));

  return (
    <ChartCard title="Top processos" subtitle="CPU relativa entre processos observados." delay={160}>
      <div className="bars compact">
        {(processes ?? []).slice(0, 5).map((process, index) => (
          <div className="bar-row reveal-row" key={process.pid} style={{ "--delay": `${index * 70}ms` }}>
            <div className="bar-labels stacked">
              <span>{process.command}</span>
              <small>
                PID {process.pid} | MEM {process.memory_percent}%
              </small>
            </div>
            <div className="bar-track">
              <div
                className="bar-fill process"
                style={{ width: `${(process.cpu_percent / maxCpu) * 100}%` }}
              />
            </div>
          </div>
        ))}
        {!(processes ?? []).length ? <p className="muted">Sem dados de processos na coleta atual.</p> : null}
      </div>
    </ChartCard>
  );
}
