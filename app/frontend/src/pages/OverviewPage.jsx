import { EmptyState } from "../components/EmptyState";
import { FindingsTable } from "../components/FindingsTable";
import { ProcessChart } from "../components/ProcessChart";
import { ScoreCards } from "../components/ScoreCards";
import { ScoreTrendChart } from "../components/ScoreTrendChart";
import { SeverityChart } from "../components/SeverityChart";
import { useState, useEffect } from "react";
import { api } from "../lib/api";

export function OverviewPage({ audit }) {
  const summary = audit.result?.summary;
  const [networkCount, setNetworkCount] = useState(null);
  const [networkLoading, setNetworkLoading] = useState(true);
  const [networkError, setNetworkError] = useState("");

  useEffect(() => {
    setNetworkLoading(true);
    setNetworkError("");
    api.listNetworkDevices()
      .then((resp) => {
        setNetworkCount(resp?.total ?? 0);
        setNetworkLoading(false);
      })
      .catch((err) => {
        setNetworkCount(null);
        setNetworkLoading(false);
        setNetworkError("Erro ao buscar rede");
      });
  }, []);

  if (!audit.result && !audit.loading) {
    return <EmptyState onStartScan={audit.startScan} loading={audit.loading} />;
  }
  return (
    <div className="page">
      <header className="hero hero-split">
        <div className="hero-main">
          <p className="eyebrow">Painel operacional</p>
          <h2>Seguranca, exposicao e capacidade em uma cabine de leitura rapida.</h2>
          <p className="hero-description">
            O layout prioriza decisao: primeiro o risco, depois o contexto tecnico e por fim o plano de acao.
          </p>
          <div className="hero-tags">
            <span className="hero-tag">host {audit.result?.machine_hostname ?? "sem coleta"}</span>
            <span className="hero-tag">distro {audit.result?.distro ?? "n/a"}</span>
            <span className="hero-tag">modo {audit.result?.mode ?? "agentless"}</span>
          </div>
        </div>
        <div className="hero-side">
          <div className="signal-card">
            <span className="eyebrow">Pulse</span>
            <strong>{audit.result?.scores?.overall ?? "--"}</strong>
            <p className="muted">Leitura agregada da postura atual.</p>
          </div>
          <div className="signal-bars">
            <span />
            <span />
            <span />
            <span />
            <span />
          </div>
        </div>
      </header>
      <ScoreCards scores={audit.result?.scores} />
      <section className="analytics-grid">
        <ScoreTrendChart scores={audit.result?.scores} />
        <SeverityChart findings={audit.result?.findings ?? []} />
      </section>
      <section className="summary-grid">
        <article className="panel">
          <h2>Resumo executivo</h2>
          <div className="metric-grid">
            <div className="metric-tile">
              <span>Usuarios humanos</span>
              <strong>{summary?.human_users ?? "--"}</strong>
            </div>
            <div className="metric-tile">
              <span>Portas em escuta</span>
              <strong>{summary?.listening_ports ?? "--"}</strong>
            </div>
            <div className="metric-tile">
              <span>Findings criticos</span>
              <strong>{summary?.critical_findings ?? "--"}</strong>
            </div>
            <div className="metric-tile">
              <span>Dispositivos na rede</span>
              <strong>
                {networkLoading
                  ? "..."
                  : networkError
                  ? "--"
                  : networkCount != null
                  ? networkCount
                  : "--"}
              </strong>
            </div>
            <div className="metric-tile">
              <span>Conexoes TCP</span>
              <strong>{summary?.established_connections ?? "--"}</strong>
            </div>
          </div>
        </article>
        <ProcessChart processes={summary?.top_processes ?? []} />
      </section>
      <FindingsTable findings={audit.result?.findings ?? []} />
    </div>
  );
}
