import { RecommendationBreakdownChart } from "../components/RecommendationBreakdownChart";
import { RecommendationList } from "../components/RecommendationList";
import { ScoreTrendChart } from "../components/ScoreTrendChart";

export function RecommendationsPage({ audit }) {
  const recommendations = audit.result?.recommendations ?? [];
  return (
    <div className="page">
      <section className="section-shell">
        <div className="section-copy">
          <p className="eyebrow">Action Room</p>
          <h2>Plano de acao desenhado para execucao segura, com prioridade, validacao e contexto.</h2>
          <p className="muted">
            As recomendacoes sao derivadas apenas de evidencias read-only e nao executam remediacao automatica.
          </p>
        </div>
        <div className="section-metrics">
          <div className="section-metric">
            <span>Acoes</span>
            <strong>{recommendations.length}</strong>
          </div>
          <div className="section-metric">
            <span>P0/P1</span>
            <strong>{recommendations.filter((item) => item.priority === "P0" || item.priority === "P1").length}</strong>
          </div>
        </div>
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
