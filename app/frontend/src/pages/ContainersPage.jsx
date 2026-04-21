import { useEffect, useState } from "react";
import { api } from "../lib/api";

function renderPorts(ports) {
  if (!ports || typeof ports !== "object") return <span className="muted">Nenhuma</span>;
  try {
    const keys = Object.keys(ports);
    if (keys.length === 0) return <span className="muted">Nenhuma</span>;
    return keys.map((key, idx) => {
      const val = ports[key];
      if (!Array.isArray(val) || val.length === 0) return <div key={idx}>Nenhuma</div>;
      const portStrs = val.filter(b => b).map((b, i) => `${b?.HostIp ?? ""}:${b?.HostPort ?? ""}`);
      if (portStrs.length === 0) return <div key={idx}>Nenhuma</div>;
      return (
        <div key={idx}>
          {key} → {portStrs.join(", ")}
        </div>
      );
    });
  } catch (e) {
    return <span className="muted">Nenhuma</span>;
  }
}

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
                  <tr key={c.id ?? Math.random()}>
                    <td>{c.name ?? "-"}</td>
                    <td>{c.image ?? "-"}</td>
                    <td><span className={`pill ${c.status === "running" ? "pill-ok" : "pill-warn"}`}>{c.status ?? "-"}</span></td>
                    <td>{renderPorts(c.ports)}</td>
                    <td><code style={{ fontSize: "0.72em" }}>{(c.id ?? "").slice(0, 12)}</code></td>
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
