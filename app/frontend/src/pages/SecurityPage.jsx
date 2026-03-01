import { FindingsTable } from "../components/FindingsTable";
import { SeverityChart } from "../components/SeverityChart";

export function SecurityPage({ audit }) {
  const explanation = audit.result?.scores?.explanation;
  return (
    <div className="page">
      <section className="analytics-grid">
        <section className="panel">
          <h2>Score de seguranca</h2>
          <p className="headline">{audit.result?.scores?.security ?? "--"}</p>
          <p>{explanation?.why?.[0] ?? "O score e calculado por severidade ponderada."}</p>
        </section>
        <SeverityChart findings={(audit.result?.findings ?? []).filter((item) => item.domain === "security")} />
      </section>
      <FindingsTable findings={audit.result?.findings ?? []} domain="security" />
    </div>
  );
}
