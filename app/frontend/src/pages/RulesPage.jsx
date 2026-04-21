import { useEffect, useState } from "react";
import { api } from "../lib/api";

export function RulesPage() {
  const [data, setData] = useState({ total: 0, enabled: 0, disabled: 0, rules: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadRules = () => {
    setLoading(true);
    api.listRules()
      .then((resp) => {
        setData(resp ?? { total: 0, enabled: 0, disabled: 0, rules: [] });
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message ?? "Erro ao buscar regras");
        setLoading(false);
      });
  };

  useEffect(() => {
    loadRules();
    const interval = setInterval(loadRules, 30000);
    return () => clearInterval(interval);
  }, []);

  const { total, enabled, disabled, rules } = data;

  return (
    <div className="page">
      <section className="section-shell">
        <div className="section-copy">
          <h2>Regras de Scanning</h2>
          <p className="muted">
            Total: <strong>{total}</strong> | 
            Ativas: <strong>{enabled}</strong> | 
            Inativas: <strong>{disabled}</strong>
          </p>
        </div>
        <button className="secondary-button" onClick={loadRules}>
          Atualizar
        </button>
      </section>
      <section className="panel">
        {loading ? (
          <div className="muted">Carregando regras...</div>
        ) : error ? (
          <div className="banner error">{error}</div>
        ) : rules.length === 0 ? (
          <div className="muted">Nenhuma regra encontrada.</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Descricao</th>
                  <th>Categoria</th>
                  <th>Severidade</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((r, idx) => (
                  <tr key={r.id || idx}>
                    <td><code>{r.id}</code></td>
                    <td>{r.description}</td>
                    <td>{r.category || "-"}</td>
                    <td>
                      <span className={`pill ${r.severity === 'CRIT' ? 'pill-warn' : r.severity === 'HIGH' ? 'pill-warn' : 'pill-ok'}`}>
                        {r.severity}
                      </span>
                    </td>
                    <td>
                      <span className={r.enabled ? "pill-ok" : "pill-warn"}>
                        {r.enabled ? "Ativa" : "Inativa"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}