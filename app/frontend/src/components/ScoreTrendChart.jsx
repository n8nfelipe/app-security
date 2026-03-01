import { ChartCard } from "./ChartCard";

export function ScoreTrendChart({ scores, rows }) {
  const resolvedRows = rows ?? [
    { label: "Geral", value: scores?.overall ?? 0, color: "var(--score-overall)" },
    { label: "Seguranca", value: scores?.security ?? 0, color: "var(--score-security)" },
    { label: "Performance", value: scores?.performance ?? 0, color: "var(--score-performance)" },
  ];

  return (
    <ChartCard title="Scores comparativos" subtitle="Escala de 0 a 100." delay={0}>
      <div className="bars">
        {resolvedRows.map((row, index) => (
          <div className="bar-row reveal-row" key={row.label} style={{ "--delay": `${index * 80}ms` }}>
            <div className="bar-labels">
              <span>{row.label}</span>
              <strong>{row.value}</strong>
            </div>
            <div className="bar-track">
              <div className="bar-fill" style={{ width: `${row.value}%`, background: row.color }} />
            </div>
          </div>
        ))}
      </div>
    </ChartCard>
  );
}
