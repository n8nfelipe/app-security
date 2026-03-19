/**
 * EmptyState — exibido quando nenhuma coleta foi realizada ainda.
 * Orienta o usuário a iniciar o primeiro scan com um CTA claro.
 */
export function EmptyState({ onStartScan, loading }) {
  return (
    <div className="empty-state">
      <div className="empty-state-icon">🛡️</div>
      <h2>Nenhuma coleta realizada</h2>
      <p className="muted">
        Clique em <strong>Nova coleta</strong> para analisar a postura de
        segurança e performance deste host.
      </p>
      <button
        className="primary-button"
        onClick={onStartScan}
        disabled={loading}
        style={{ marginTop: "1.5rem" }}
      >
        {loading ? "Coletando..." : "Iniciar primeira coleta"}
      </button>
      <p className="muted" style={{ marginTop: "1rem", fontSize: "0.8rem" }}>
        A coleta é read-only: nenhuma alteração é feita no sistema.
      </p>
    </div>
  );
}
