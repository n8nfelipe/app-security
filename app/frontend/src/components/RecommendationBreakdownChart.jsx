import { ChartCard } from "./ChartCard";

const PRIORITIES = ["P0", "P1", "P2", "P3", "P4"];

export function RecommendationBreakdownChart({ recommendations }) {
  const items = PRIORITIES.map((priority) => ({
    priority,
    count: recommendations.filter((item) => item.priority === priority).length,
  }));
  const maxCount = Math.max(1, ...items.map((item) => item.count));

  return (
    <ChartCard title="Plano por prioridade" subtitle="Volume de acoes por urgencia." delay={120}>
      <div className="bars">
        {items.map((item, index) => (
          <div className="bar-row reveal-row" key={item.priority} style={{ "--delay": `${index * 80}ms` }}>
            <div className="bar-labels">
              <span>{item.priority}</span>
              <strong>{item.count}</strong>
            </div>
            <div className="bar-track">
              <div
                className={`bar-fill priority-${item.priority.toLowerCase()}`}
                style={{ width: `${(item.count / maxCount) * 100}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </ChartCard>
  );
}
