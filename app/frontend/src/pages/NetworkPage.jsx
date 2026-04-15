export function NetworkPage({ audit }) {
  const summary = audit.result?.summary;
  const networkDetails = summary?.network_details ?? {};
  const listeningPorts = networkDetails?.listening_ports ?? [];
  const establishedConnections = networkDetails?.established_connections ?? [];

  if (!audit.result && !audit.loading) {
    return (
      <div className="page">
        <section className="panel empty-state">
          <div className="empty-state-icon">🌐</div>
          <h2>Nenhuma coleta disponivel</h2>
          <p className="muted">Execute uma nova coleta para visualizar os dados de rede.</p>
        </section>
      </div>
    );
  }

  return (
    <div className="page">
      <section className="section-shell">
        <div className="section-copy">
          <p className="eyebrow">Network Lens</p>
          <h2>Portas, conexoes e superficie de rede exposta.</h2>
          <p className="muted">
            Visao detalhada das portas em escuta e conexoes TCP/UDP ativas no host.
          </p>
        </div>
        <div className="section-metrics">
          <div className="section-metric">
            <span>Portas escutando</span>
            <strong>{summary?.listening_ports ?? "--"}</strong>
          </div>
          <div className="section-metric">
            <span>Conexoes TCP</span>
            <strong>{summary?.established_connections ?? "--"}</strong>
          </div>
        </div>
      </section>

      <section className="panel">
        <h2>Portas em escuta</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Protocolo</th>
                <th>Estado</th>
                <th>Endereco</th>
              </tr>
            </thead>
            <tbody>
              {listeningPorts.map((port, idx) => (
                <tr key={idx}>
                  <td>{port.protocol}</td>
                  <td>
                    <span className="pill">{port.state}</span>
                  </td>
                  <td>
                    <code>{port.address}</code>
                  </td>
                </tr>
              ))}
              {!listeningPorts.length && (
                <tr>
                  <td colSpan={3} className="muted">
                    Nenhuma porta em escuta detectada.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel">
        <h2>Conexoes TCP estabelecidas</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Protocolo</th>
                <th>Local</th>
                <th>Remoto</th>
                <th>Estado</th>
              </tr>
            </thead>
            <tbody>
              {establishedConnections.map((conn, idx) => (
                <tr key={idx}>
                  <td>{conn.protocol}</td>
                  <td>
                    <code>{conn.local_address}</code>
                  </td>
                  <td>
                    <code>{conn.remote_address}</code>
                  </td>
                  <td>
                    <span className="pill">{conn.state}</span>
                  </td>
                </tr>
              ))}
              {!establishedConnections.length && (
                <tr>
                  <td colSpan={4} className="muted">
                    Nenhuma conexao TCP estabelecida detectada.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}