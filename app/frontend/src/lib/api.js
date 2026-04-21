const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000/api/v1";
const API_TOKEN = import.meta.env.VITE_API_TOKEN ?? "changeme-token";

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "X-API-Token": API_TOKEN,
      ...(options.headers ?? {}),
    },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail ?? `HTTP ${response.status}`);
  }
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/pdf")) {
    return response.blob();
  }
  return response.json();
}

export const api = {
  listContainers: () => request("/containers"),
  listNetworkDevices: () => request("/network/devices"),
  listUsers: () => request("/users"),
  listRules: () => request("/rules"),
  createScan: () => request("/scans", { method: "POST", body: JSON.stringify({ mode: "agentless" }) }),
  scanStatus: (scanId) => request(`/scans/${scanId}/status`),
  scanResults: (scanId) => request(`/scans/${scanId}/results`),
  history: () => request("/history"),
  exportJson: (scanId) => request(`/scans/${scanId}/export/json`),
  exportPdf: (scanId) => request(`/scans/${scanId}/export/pdf`, { headers: { Accept: "application/pdf" } }),
};
