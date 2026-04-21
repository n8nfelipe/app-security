import { useEffect, useState } from "react";
import { api } from "../lib/api";

export function ContainersPage() {
  const [containers, setContainers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    setLoading(true);
    api.listContainers()
      .then((resp) => {
        setContainers(resp.containers ?? []);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message ?? "Erro buscando containers");
        setLoading(false);
      });
  }, []);

  return (
    <div className="page">
      <section className="section-shell">
        <div className="section-copy">
          <h2>Containers Docker em execução</h2>
          <p className="muted">Lista atual dos containers em execução no host auditado.</p>
        </div>
      </section>
      <section className="panel">
        {loading ? (
          <div className="muted">Carregando containers…</div>
        ) : error ? (
          <div className="banner error">{error}</div>
        ) : containers.length === 0 ? (
          <div className="muted">Nenhum container em execução.</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Nome</th>
                  <th>Imagem</th>
                  <th>Status</th>
                  <th>Portas</th>
                  <th>ID</th>
                </tr>
              </thead>
              <tbody>
                {containers.map((c) => (
                  <tr key={c.id}>
                    <td>{c.name}</td>
                    <td>{c.image}</td>
                    <td><span className={`pill ${c.status === "running" ? "pill-ok" : "pill-warn"}`}>{c.status}</span></td>
                    <td>
                      {c.ports && Object.keys(c.ports).length ?
                        Object.entries(c.ports).map(([key, val], idx) => (
                          <div key={idx}>
                            {key} →
                            {val.map((b, i) => `${b.HostIp}:${b.HostPort}`).join(", ")}
                          </div>
                        )) : <span className="muted">Nenhuma</span>}
                    </td>
                    <td><code style={{ fontSize: "0.72em" }}>{c.id.slice(0, 12)}</code></td>
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
