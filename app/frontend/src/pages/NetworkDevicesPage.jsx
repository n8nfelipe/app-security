import { useEffect, useState } from "react";
import { api } from "../lib/api";

export function NetworkDevicesPage() {
  const [data, setData] = useState({ total: 0, devices: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refreshing, setRefreshing] = useState(false);

  const loadDevices = (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);
    api.listNetworkDevices()
      .then((resp) => {
        setData(resp ?? { total: 0, devices: [] });
        setLoading(false);
        setRefreshing(false);
      })
      .catch((err) => {
        setError(err.message ?? "Erro buscando dispositivos");
        setLoading(false);
        setRefreshing(false);
      });
  };

  useEffect(() => {
    loadDevices();
  }, []);

  const devices = data.devices ?? [];
  const total = data.total ?? 0;

  return (
    <div className="page">
      <section className="section-shell">
        <div className="section-copy">
          <h2>Dispositivos na rede local</h2>
          <p className="muted">
            Total: <strong>{total}</strong> dispositivos ativos detectados na rede LAN.
          </p>
        </div>
        <button
          className="secondary-button"
          onClick={() => loadDevices(true)}
          disabled={refreshing}
        >
          {refreshing ? "Atualizando..." : "Atualizar"}
        </button>
      </section>
      <section className="panel">
        {loading ? (
          <div className="muted">Carregando dispositivos…</div>
        ) : error ? (
          <div className="banner error">{error}</div>
        ) : devices.length === 0 ? (
          <div className="muted">Nenhum dispositivo encontrado.</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Hostname</th>
                  <th>MAC</th>
                  <th>Fabricante</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {devices.map((d, idx) => (
                  <tr key={d.ip || idx}>
                    <td><code>{d.ip}</code></td>
                    <td>{d.hostname || "-"}</td>
                    <td><code style={{ fontSize: "0.8em" }}>{d.mac || "-"}</code></td>
                    <td>{d.vendor || "-"}</td>
                    <td>
                      <span className={`pill ${d.state === "up" ? "pill-ok" : "pill-warn"}`}>
                        {d.state}
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
