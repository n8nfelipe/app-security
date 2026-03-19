import { useMemo, useState } from "react";

export function FindingsTable({ findings, domain }) {
  const [severity, setSeverity] = useState("ALL");
  const rows = useMemo(() => {
    return findings
      .filter((item) => (domain ? item.domain === domain : true))
      .filter((item) => (severity === "ALL" ? true : item.severity === severity));
  }, [domain, findings, severity]);

  return (
    <section className="panel">
      <div className="investigation-header">
        <div>
          <p className="eyebrow">Investigation Board</p>
          <h2>Findings priorizados</h2>
        </div>
        <div className="investigation-controls">
          <span className="result-count">{rows.length} itens</span>
          <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
            <option value="ALL">Todas severidades</option>
            <option value="CRIT">CRIT</option>
            <option value="HIGH">HIGH</option>
            <option value="MED">MED</option>
            <option value="LOW">LOW</option>
            <option value="INFO">INFO</option>
          </select>
        </div>
      </div>
      <div className="finding-board">
        {rows.map((item) => (
          <article className={`finding-card severity-${item.severity.toLowerCase()}`} key={`${item.id}-${item.check_id}`}>
            <div className="finding-topline">
              <span className="finding-severity">{item.severity}</span>
              <span className="finding-check">{item.check_id}</span>
            </div>
            <div className="finding-copy">
              <strong>{item.title}</strong>
              <p className="cell-detail">{item.rationale}</p>
            </div>
            <div className="finding-grid">
              <div className="finding-block">
                <span className="finding-label">Evidencia</span>
                <p>{item.evidence}</p>
              </div>
              <div className="finding-block">
                <span className="finding-label">Acao sugerida</span>
                <p>{item.recommendation}</p>
              </div>
            </div>
            {["HIGH", "CRIT"].includes(item.severity) && item.metadata?.remediation ? (
              <div className="fix-guide">
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
              </div>
            ) : null}
          </article>
        ))}
        {!rows.length ? <div className="empty-findings">Nenhum finding para o filtro atual.</div> : null}
      </div>
    </section>
  );
}
