import { ChartCard } from "./ChartCard";

export function HistoryTrendChart({ history }) {
  const items = (history ?? []).filter((item) => typeof item.overall_score === "number").slice(0, 8).reverse();
  const points = items
    .map((item, index) => {
      const x = items.length > 1 ? (index / (items.length - 1)) * 220 : 110;
      const y = 120 - ((item.overall_score ?? 0) / 100) * 100;
      return `${x},${y}`;
    })
    .join(" ");

  return (
    <ChartCard title="Tendencia do historico" subtitle="Ultimas coletas com score geral." delay={80}>
      <div className="history-chart">
        <svg viewBox="0 0 220 140" className="line-chart" aria-label="Historico de scores">
          <defs>
            <linearGradient id="historyGradient" x1="0%" x2="100%" y1="0%" y2="0%">
              <stop offset="0%" stopColor="var(--accent)" />
              <stop offset="100%" stopColor="var(--accent-2)" />
            </linearGradient>
          </defs>
          <path className="line-grid" d="M0 20H220 M0 60H220 M0 100H220 M0 120H220" />
          {points ? <polyline className="line-path" points={points} /> : null}
          {items.map((item, index) => {
            const x = items.length > 1 ? (index / (items.length - 1)) * 220 : 110;
            const y = 120 - ((item.overall_score ?? 0) / 100) * 100;
            return (
              <g key={item.scan_id} className="line-point-group" style={{ "--delay": `${index * 90}ms` }}>
                <circle cx={x} cy={y} r="4" className="line-point" />
              </g>
            );
          })}
        </svg>
        <div className="history-summary">
          {items.map((item, index) => (
            <div className="history-pill reveal-row" key={item.scan_id} style={{ "--delay": `${120 + index * 60}ms` }}>
              <span>{item.machine_hostname ?? "host"}</span>
              <strong>{item.overall_score}</strong>
            </div>
          ))}
          {!items.length ? <p className="muted">Sem scans suficientes para mostrar tendencia.</p> : null}
        </div>
      </div>
    </ChartCard>
  );
}
