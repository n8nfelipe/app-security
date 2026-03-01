import { useEffect, useRef, useState } from "react";

import { api } from "./api";

export function useAuditData() {
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const lastScanId = useRef(null);

  async function refreshHistory() {
    try {
      const response = await api.history();
      setHistory(response.items);
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => {
    refreshHistory();
  }, []);

  async function pollUntilComplete(scanId) {
    for (let attempt = 0; attempt < 12; attempt += 1) {
      const status = await api.scanStatus(scanId);
      if (status.status === "completed") {
        const payload = await api.scanResults(scanId);
        setResult(payload);
        setNotice(`Coleta concluida para ${payload.machine_hostname ?? "host local"}.`);
        await refreshHistory();
        return;
      }
      if (status.status === "failed") {
        throw new Error(status.error_message ?? "Falha segura durante a coleta.");
      }
      await new Promise((resolve) => setTimeout(resolve, 1500));
    }
    throw new Error("Timeout aguardando a conclusao da coleta.");
  }

  async function startScan() {
    setLoading(true);
    setError("");
    setNotice("Coleta read-only iniciada.");
    try {
      const created = await api.createScan();
      lastScanId.current = created.scan_id;
      await pollUntilComplete(created.scan_id);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function exportJson() {
    if (!result) {
      return;
    }
    const payload = await api.exportJson(result.scan_id);
    const blob = new Blob([JSON.stringify(payload.payload, null, 2)], { type: "application/json" });
    download(blob, payload.file_name);
  }

  async function exportPdf() {
    if (!result) {
      return;
    }
    const blob = await api.exportPdf(result.scan_id);
    download(blob, `${result.scan_id}.pdf`);
  }

  return {
    result,
    history,
    loading,
    error,
    notice,
    startScan,
    exportJson,
    exportPdf,
  };
}

function download(blob, fileName) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName;
  anchor.click();
  URL.revokeObjectURL(url);
}
