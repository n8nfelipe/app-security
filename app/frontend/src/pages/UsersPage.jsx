import { useEffect, useState, useCallback } from "react";
import { api } from "../lib/api";

export function UsersPage() {
  const [data, setData] = useState({ total: 0, human_users: 0, users: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refreshing, setRefreshing] = useState(false);

  const loadUsers = useCallback((isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);
    api.listUsers()
      .then((resp) => {
        setData(resp ?? { total: 0, human_users: 0, users: [] });
        setLoading(false);
        setRefreshing(false);
      })
      .catch((err) => {
        setError(err.message ?? "Erro ao buscar usuarios");
        setLoading(false);
        setRefreshing(false);
      });
  }, []);

  useEffect(() => {
    loadUsers();
    const interval = setInterval(() => loadUsers(true), 15000);
    return () => clearInterval(interval);
  }, [loadUsers]);

  const { total, human_users, users } = data;

  return (
    <div className="page">
      <section className="section-shell">
        <div className="section-copy">
          <h2>Usuarios do sistema</h2>
          <p className="muted">
            Total: <strong>{total}</strong> contas | 
            Humanos: <strong>{human_users}</strong> (UID &gt;= 1000)
          </p>
        </div>
        <button className="secondary-button" onClick={() => loadUsers(true)} disabled={refreshing}>
          {refreshing ? "Atualizando..." : "Atualizar"}
        </button>
      </section>
      <section className="panel">
        {loading ? (
          <div className="muted">Carregando usuarios...</div>
        ) : error ? (
          <div className="banner error">{error}</div>
        ) : users.length === 0 ? (
          <div className="muted">Nenhum usuario encontrado.</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Usuario</th>
                  <th>UID</th>
                  <th>GID</th>
                  <th>Diretorio</th>
                  <th>Shell</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u, idx) => (
                  <tr key={u.username || idx}>
                    <td><code>{u.username}</code></td>
                    <td>{u.uid}</td>
                    <td>{u.gid}</td>
                    <td><code style={{ fontSize: "0.8em" }}>{u.home}</code></td>
                    <td><code>{u.shell}</code></td>
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