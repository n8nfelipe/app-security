import { FindingsTable } from "../components/FindingsTable";
import { SeverityChart } from "../components/SeverityChart";

export function SecurityPage({ audit }) {
  const explanation = audit.result?.scores?.explanation;
  const securityFindings = (audit.result?.findings ?? []).filter((item) => item.domain === "security");
  return (
    <div className="page">
      <section className="section-shell">
        <div className="section-copy">
          <p className="eyebrow">Security Lens</p>
          <h2>Exposicao, identidade e configuracao defensiva em uma leitura focada.</h2>
          <p className="muted">
            Esta visao destaca o que amplia superficie de ataque e o que merece endurecimento imediato.
          </p>
        </div>
        <div className="section-metrics">
          <div className="section-metric">
            <span>Score</span>
            <strong>{audit.result?.scores?.security ?? "--"}</strong>
          </div>
          <div className="section-metric">
            <span>Achados</span>
            <strong>{securityFindings.length}</strong>
          </div>
        </div>
      </section>
      <section className="analytics-grid">
        <section className="panel">
          <h2>Score de seguranca</h2>
          <p className="headline">{audit.result?.scores?.security ?? "--"}</p>
          <p>{explanation?.why?.[0] ?? "O score e calculado por severidade ponderada."}</p>
        </section>
        <SeverityChart findings={securityFindings} />
      </section>
      <FindingsTable findings={audit.result?.findings ?? []} domain="security" />
    </div>
  );
}
