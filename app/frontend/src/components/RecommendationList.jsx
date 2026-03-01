export function RecommendationList({ recommendations }) {
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Plano de acao</h2>
        <p className="muted">Ordenado por prioridade, impacto e risco operacional.</p>
      </div>
      <div className="recommendation-list">
        {recommendations.map((item) => (
          <article className="recommendation-card" key={`${item.id}-${item.source_check_id}`}>
            <header>
              <span className="pill">{item.priority}</span>
              <strong>{item.title}</strong>
            </header>
            <p>{item.action}</p>
            <small>
              Dominio {item.domain} | risco {item.risk} | impacto {item.impact} | esforco {item.effort}
            </small>
            {item.metadata?.remediation ? (
              <div className="fix-guide recommendation-guide">
                <strong>Como corrigir</strong>
                <ul>
                  {item.metadata.remediation.steps.map((step) => (
                    <li key={step}>{step}</li>
                  ))}
                </ul>
                <strong>Como validar</strong>
                <ul>
                  {item.metadata.remediation.verify.map((step) => (
                    <li key={step}>{step}</li>
                  ))}
                </ul>
                {item.metadata.reference ? <small>Referencia: {item.metadata.reference}</small> : null}
              </div>
            ) : null}
          </article>
        ))}
        {!recommendations.length ? <p>Nenhuma recomendacao disponivel.</p> : null}
      </div>
    </section>
  );
}
