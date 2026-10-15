const BASE = '/api/v1'
const TOKEN_KEY = 'k1z-api-token'

export function getToken() {
  return localStorage.getItem(TOKEN_KEY) || ''
}
export function setToken(t) {
  t ? localStorage.setItem(TOKEN_KEY, t) : localStorage.removeItem(TOKEN_KEY)
}

function headers(extra = {}) {
  const h = { ...extra }
  const token = getToken()
  if (token) h['Authorization'] = `Bearer ${token}`
  return h
}

async function req(method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: headers(body ? { 'Content-Type': 'application/json' } : {}),
    body: body ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    if (res.status === 401) window.dispatchEvent(new CustomEvent('k1z:unauthorized'))
    throw new Error(err.detail || res.statusText)
  }
  if (res.status === 204) return null
  return res.json()
}

export const api = {
  // Auth / system
  authStatus: () => req('GET', '/auth/status'),
  getHealth:  () => req('GET', '/health'),

  // Network & DNS diagnostics + one-click fix
  networkCheck: () => req('GET', '/network/check'),
  networkFix:   (body = {}) => req('POST', '/network/fix', body),

  // Workflows
  getWorkflows:   () => req('GET', '/workflows'),
  getWorkflow:    (name) => req('GET', `/workflows/${encodeURIComponent(name)}`),
  saveWorkflow:   (name, body) => req('PUT', `/workflows/${encodeURIComponent(name)}`, body),
  deleteWorkflow: (name) => req('DELETE', `/workflows/${encodeURIComponent(name)}`),
  importWorkflow: (name, yamlText) => req('POST', '/workflows/import', { name, yaml_text: yamlText }),
  workflowHistory: (name) => req('GET', `/workflows/${encodeURIComponent(name)}/history`),
  workflowDownloadUrl: (name) => `${BASE}/workflows/${encodeURIComponent(name)}/download`,

  // Runs
  getRuns: (params = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null)).toString()
    return req('GET', `/runs${qs ? '?' + qs : ''}`)
  },
  getStats: () => req('GET', '/runs/stats'),
  getRun: (id) => req('GET', `/runs/${id}`),
  createRun: (body) => req('POST', '/runs', body),
  cancelRun: (id) => req('POST', `/runs/${id}/cancel`),
  pauseRun:       (id) => req('POST',   `/runs/${id}/pause`),
  cancelPause:    (id) => req('DELETE', `/runs/${id}/pause`),
  resumeRun:      (id) => req('POST',   `/runs/${id}/resume`),
  deleteRun: (id) => req('DELETE', `/runs/${id}`),
  getNewAssets: (id) => req('GET', `/runs/${id}/new-assets`),

  // Logs (paginated)
  getLogs: (id, params = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null)).toString()
    return req('GET', `/runs/${id}/logs${qs ? '?' + qs : ''}`)
  },

  // Files
  getFiles: (runId) => req('GET', `/runs/${runId}/files`),
  getScreenshots: (runId) => req('GET', `/runs/${runId}/screenshots`),
  getFileContent: (runId, path) =>
    fetch(`${BASE}/runs/${runId}/files/${path.split('/').map(encodeURIComponent).join('/')}`,
          { headers: headers() }).then(r => r.text()),

  // Findings
  getFindings: (params = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null)).toString()
    return req('GET', `/findings${qs ? '?' + qs : ''}`)
  },
  getFindingsStats: () => req('GET', '/findings/stats'),
  getRunFindings: (runId, params = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null)).toString()
    return req('GET', `/runs/${runId}/findings${qs ? '?' + qs : ''}`)
  },
  patchFinding: (id, body) => req('PATCH', `/findings/${id}`, body),
  reparseFinding: (runId) => req('POST', `/runs/${runId}/findings/reparse`),
  getDuplicates: () => req('GET', '/findings/duplicates'),
  resolveDuplicates: () => req('POST', '/findings/duplicates/resolve'),

  // Reports
  reportUrl: (runId) => `${BASE}/runs/${runId}/report`,
  reportDraftUrl: (runId, format = 'hackerone') => `${BASE}/runs/${runId}/report-draft?format=${format}`,

  // Schedules (continuous recon)
  getSchedules:    () => req('GET', '/schedules'),
  createSchedule:  (body) => req('POST', '/schedules', body),
  patchSchedule:   (id, body) => req('PATCH', `/schedules/${id}`, body),
  deleteSchedule:  (id) => req('DELETE', `/schedules/${id}`),
  triggerSchedule: (id) => req('POST', `/schedules/${id}/trigger`),

  // Targets (target-centric view + scope)
  getTargets:    () => req('GET', '/targets'),
  createTarget:  (body) => req('POST', '/targets', body),
  getTarget:     (name) => req('GET', `/targets/${encodeURIComponent(name)}`),
  patchTarget:   (name, body) => req('PATCH', `/targets/${encodeURIComponent(name)}`, body),
  deleteTarget:  (name) => req('DELETE', `/targets/${encodeURIComponent(name)}`),
  getTargetAudit: (name) => req('GET', `/targets/${encodeURIComponent(name)}/audit`),
  targetNewAssets: (name) => req('GET', `/targets/${encodeURIComponent(name)}/new-assets`),
  scopeCheck:    (host) => req('GET', `/scope/check?host=${encodeURIComponent(host)}`),

  // Tools
  getTools: () => req('GET', '/tools'),
  checkToolVersions: () => req('POST', '/tools/check'),
  updateTools: (body = {}) => req('POST', '/tools/update', body),

  // Asset Inventory (cross-run deduped http findings)
  getAssets: (params = {}) => {
    const entries = []
    for (const [k, v] of Object.entries(params)) {
      if (Array.isArray(v)) v.forEach(x => entries.push([k, x]))
      else if (v != null) entries.push([k, v])
    }
    const s = new URLSearchParams(entries).toString()
    return req('GET', `/assets${s ? '?' + s : ''}`)
  },
  getAssetsStats: () => req('GET', '/assets/stats'),
  deleteAsset: (host, port) => req('DELETE', '/assets', { host, port: port ?? null }),

  // API Keys
  getKeys:      () => req('GET', '/keys'),
  getKeysStats: () => req('GET', '/keys/stats'),
  getEnvStatus: () => req('GET', '/keys/env-status'),
  setKey:       (provider, value) => req('PUT', `/keys/${provider}`, { value }),
  deleteKey:    (provider) => req('DELETE', `/keys/${provider}`),

  // System (danger zone: reset DB + wipe run workspaces)
  getSystemUsage: () => req('GET', '/system/usage'),
  resetSystem:    (scope, confirm) => req('POST', '/system/reset', { scope, confirm }),
}

export function wsUrl(runId) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  const token = getToken()
  const qs = token ? `?token=${encodeURIComponent(token)}` : ''
  return `${proto}://${location.host}/ws/runs/${runId}${qs}`
}
