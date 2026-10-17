// Minimal fetch shim for the ported legacy k1nzr3c0n pages (WorkflowEditor).
// Mirrors the old frontend/src/api.js surface they import, routed at /api/v1/*.
// k1z's own auth is disabled by default; we still attach ScopeWeaver's bearer
// token if present so it works when a token is configured.
const BASE = "/api/v1";

export function getToken() {
  try {
    return localStorage.getItem("artex_token") || "";
  } catch {
    return "";
  }
}

function headers(extra = {}) {
  const h = { ...extra };
  const token = getToken();
  if (token) h["Authorization"] = `Bearer ${token}`;
  return h;
}

async function req(method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: headers(body ? { "Content-Type": "application/json" } : {}),
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || res.statusText);
  }
  if (res.status === 204) return null;
  return res.json();
}

export const api = {
  getWorkflows: () => req("GET", "/workflows"),
  getWorkflow: (name) => req("GET", `/workflows/${encodeURIComponent(name)}`),
  saveWorkflow: (name, body) => req("PUT", `/workflows/${encodeURIComponent(name)}`, body),
  deleteWorkflow: (name) => req("DELETE", `/workflows/${encodeURIComponent(name)}`),
  importWorkflow: (name, yamlText) => req("POST", "/workflows/import", { name, yaml_text: yamlText }),
  createRun: (body) => req("POST", "/runs", body),
  getTools: () => req("GET", "/tools"),
};

export function wsUrl(runId) {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const token = getToken();
  const qs = token ? `?token=${encodeURIComponent(token)}` : "";
  return `${proto}://${location.host}/ws/runs/${runId}${qs}`;
}
