import { HistoryTrendChart } from "../components/HistoryTrendChart";
import { ScoreTrendChart } from "../components/ScoreTrendChart";

export function HistoryPage({ audit }) {
  return (
    <div className="page">
      <section className="section-shell">
        <div className="section-copy">
          <p className="eyebrow">History Lens</p>
          <h2>Evolucao de postura por host, com contexto de tendencia e memoria operacional.</h2>
          <p className="muted">Use esta camada para perceber melhora, regressao e variacao de baseline.</p>
        </div>
        <div className="section-metrics">
          <div className="section-metric">
            <span>Scans</span>
            <strong>{audit.history.length}</strong>
          </div>
          <div className="section-metric">
            <span>Ultimo host</span>
            <strong>{audit.history[0]?.machine_hostname ?? "--"}</strong>
          </div>
        </div>
      </section>
      <section className="analytics-grid">
        <HistoryTrendChart history={audit.history} />
        <ScoreTrendChart
          rows={[
            {
              label: "Media geral",
              value: audit.history.length
                ? Math.round(audit.history.reduce((sum, item) => sum + (item.overall_score ?? 0), 0) / audit.history.length)
                : 0,
              color: "var(--score-overall)",
            },
            {
              label: "Media seguranca",
              value: audit.history.length
                ? Math.round(audit.history.reduce((sum, item) => sum + (item.security_score ?? 0), 0) / audit.history.length)
                : 0,
              color: "var(--score-security)",
            },
            {
              label: "Media performance",
              value: audit.history.length
                ? Math.round(audit.history.reduce((sum, item) => sum + (item.performance_score ?? 0), 0) / audit.history.length)
                : 0,
              color: "var(--score-performance)",
            },
          ]}
        />
      </section>
      <section className="panel history-ledger">
        <div className="panel-header">
          <h2>Historico por maquina</h2>
          <p className="muted">Correlacao por hostname e machine-id quando disponivel.</p>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Scan</th>
                <th>Host</th>
                <th>Status</th>
                <th>Seg</th>
                <th>Perf</th>
                <th>Geral</th>
              </tr>
            </thead>
            <tbody>
              {audit.history.map((item) => (
                <tr key={item.scan_id} className="ledger-row">
                  <td>{item.scan_id.slice(0, 8)}</td>
                  <td>{item.machine_hostname ?? "n/a"}</td>
                  <td>{item.status}</td>
                  <td>{item.security_score ?? "--"}</td>
                  <td>{item.performance_score ?? "--"}</td>
                  <td>{item.overall_score ?? "--"}</td>
                </tr>
              ))}
              {!audit.history.length ? (
                <tr>
                  <td colSpan="6">Historico vazio.</td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
