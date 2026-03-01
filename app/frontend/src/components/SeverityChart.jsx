import { ChartCard } from "./ChartCard";

const COLORS = {
  CRIT: "#ff5d73",
  HIGH: "#ff9b5f",
  MED: "#ffd166",
  LOW: "#63e6be",
  INFO: "#66b3ff",
};

export function SeverityChart({ findings }) {
  const counts = ["CRIT", "HIGH", "MED", "LOW", "INFO"].map((severity) => ({
    severity,
    value: findings.filter((item) => item.severity === severity).length,
    color: COLORS[severity],
  }));
  const total = counts.reduce((sum, item) => sum + item.value, 0);
  let offset = 0;

  return (
    <ChartCard title="Distribuicao por severidade" subtitle="Leitura rapida do risco operacional." delay={40}>
      <div className="severity-layout">
        <svg viewBox="0 0 42 42" className="donut-chart" aria-label="Grafico de severidade">
          <circle className="donut-track" cx="21" cy="21" r="15.915" />
          {counts.map((item) => {
            const fraction = total ? item.value / total : 0;
            const dash = `${fraction * 100} ${100 - fraction * 100}`;
            const currentOffset = offset;
            offset += fraction * 100;
            return (
              <circle
                key={item.severity}
                className="donut-segment"
                cx="21"
                cy="21"
                r="15.915"
                stroke={item.color}
                strokeDasharray={dash}
                strokeDashoffset={25 - currentOffset}
              />
            );
          })}
          <text x="21" y="19.5" textAnchor="middle" className="donut-label">
            {total}
          </text>
          <text x="21" y="24" textAnchor="middle" className="donut-subtitle">
            findings
          </text>
        </svg>
        <div className="legend">
          {counts.map((item, index) => (
            <div className="legend-row reveal-row" key={item.severity} style={{ "--delay": `${120 + index * 60}ms` }}>
              <span className="legend-swatch" style={{ backgroundColor: item.color }} />
              <span>{item.severity}</span>
              <strong>{item.value}</strong>
            </div>
          ))}
        </div>
      </div>
    </ChartCard>
  );
}
