import { RecommendationBreakdownChart } from "../components/RecommendationBreakdownChart";
import { RecommendationList } from "../components/RecommendationList";
import { ScoreTrendChart } from "../components/ScoreTrendChart";

export function RecommendationsPage({ audit }) {
  const recommendations = audit.result?.recommendations ?? [];
  return (
    <div className="page">
      <section className="panel">
        <h2>Gerar plano de acao</h2>
        <p>
          As recomendacoes sao derivadas apenas de evidencias read-only e nao executam remediacao automatica.
        </p>
      </section>
      <section className="analytics-grid">
        <RecommendationBreakdownChart recommendations={recommendations} />
        <ScoreTrendChart
          rows={[
            {
              label: "Acoes de alto impacto",
              value: recommendations.filter((item) => item.impact === "high").length * 20,
              color: "var(--score-performance)",
            },
            {
              label: "Baixo risco",
              value: recommendations.filter((item) => item.risk === "low").length * 20,
              color: "var(--score-security)",
            },
            {
              label: "Baixo esforco",
              value: recommendations.filter((item) => item.effort === "low").length * 20,
              color: "var(--score-overall)",
            },
          ].map((item) => ({ ...item, value: Math.min(100, item.value) }))}
        />
      </section>
      <RecommendationList recommendations={recommendations} />
    </div>
  );
}
