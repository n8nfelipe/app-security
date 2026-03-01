import { HistoryTrendChart } from "../components/HistoryTrendChart";
import { ScoreTrendChart } from "../components/ScoreTrendChart";

export function HistoryPage({ audit }) {
  return (
    <div className="page">
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
      <section className="panel">
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
                <tr key={item.scan_id}>
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
