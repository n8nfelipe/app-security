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
      <div className="panel-header">
        <h2>Findings priorizados</h2>
        <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
          <option value="ALL">Todas severidades</option>
          <option value="CRIT">CRIT</option>
          <option value="HIGH">HIGH</option>
          <option value="MED">MED</option>
          <option value="LOW">LOW</option>
          <option value="INFO">INFO</option>
        </select>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Sev</th>
              <th>Check</th>
              <th>Titulo</th>
              <th>Evidencia</th>
              <th>Acao</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((item) => (
              <tr key={`${item.id}-${item.check_id}`}>
                <td>{item.severity}</td>
                <td>{item.check_id}</td>
                <td>
                  <strong>{item.title}</strong>
                  <p className="cell-detail">{item.rationale}</p>
                </td>
                <td>{item.evidence}</td>
                <td>
                  <p>{item.recommendation}</p>
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
                </td>
              </tr>
            ))}
            {!rows.length ? (
              <tr>
                <td colSpan="5">Nenhum finding para o filtro atual.</td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </section>
  );
}
