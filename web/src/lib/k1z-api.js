const BASE = '/api/v1'
const TOKEN_KEY = 'artex_token'

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
    if (res.status === 401) if (typeof window !== 'undefined') window.dispatchEvent(new CustomEvent('k1z:unauthorized'))
    throw new Error(err.detail || res.statusText)
  }
  if (res.status === 204) return null
  return res.json()
}

export const api = {
  // Auth / system
  authStatus: () => req('GET', '/auth/status'),
  getHealth:  () => req('GET', '/health'),

  // AI agent layer
  listLLM:        () => req('GET', '/llm'),
  createLLM:      (body) => req('POST', '/llm', body),
  deleteLLM:      (id) => req('DELETE', `/llm/${id}`),
  listConvs:      () => req('GET', '/agent/conversations'),
  convMessages:   (id) => req('GET', `/agent/conversations/${id}/messages`),
  deleteConv:     (id) => req('DELETE', `/agent/conversations/${id}`),
  renameConv:     (id, title) => req('PATCH', `/agent/conversations/${id}`, { title }),
  pinConv:        (id, pinned) => req('POST', `/agent/conversations/${id}/pin`, { pinned }),
  deleteConvsBatch: (ids) => req('POST', '/agent/conversations/delete/batch', { ids }),
  chatMentions:   (q, kind = '') => req('GET', `/chat/mentions?q=${encodeURIComponent(q)}${kind ? `&kind=${kind}` : ''}`),
  chatAgents:     () => req('GET', '/chat/agents'),
  stopChat:       (id) => req('POST', `/agent/conversations/${id}/stop`),
  chatUpload:     async (file) => {
    const fd = new FormData(); fd.append('file', file)
    const res = await fetch(BASE + '/chat/upload', { method: 'POST', headers: headers(), body: fd })
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || res.statusText)
    return res.json()
  },
  agentChat:      (body) => req('POST', '/agent/chat', body),
  agentChatStream: async (body, onEvent, signal) => {
    const res = await fetch(BASE + '/agent/chat/stream', {
      method: 'POST', headers: headers({ 'Content-Type': 'application/json' }),
      body: JSON.stringify(body), signal,
    })
    if (!res.ok || !res.body) throw new Error((await res.json().catch(() => ({}))).detail || res.statusText)
    const reader = res.body.getReader(); const dec = new TextDecoder(); let buf = ''
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      buf += dec.decode(value, { stream: true })
      let i
      while ((i = buf.indexOf('\n\n')) >= 0) {
        const chunk = buf.slice(0, i); buf = buf.slice(i + 2)
        const line = chunk.split('\n').find(l => l.startsWith('data:'))
        if (!line) continue
        try { onEvent(JSON.parse(line.slice(5).trim())) } catch {}
      }
    }
  },
  llmUsage:       () => req('GET', '/llm/usage'),
  agentRules:     () => req('GET', '/agent/rules'),
  createAgentRule:(body) => req('POST', '/agent/rules', body),
  deleteAgentRule:(id) => req('DELETE', `/agent/rules/${id}`),
  agentAudit:     (limit) => req('GET', `/agent/audit?limit=${limit || 50}`),
  skillsList:     () => req('GET', '/skills'),
  skillOverview:  () => req('GET', '/skills/overview'),
  skillFiles:     (name) => req('GET', `/skills/${encodeURIComponent(name)}/files`),
  skillFileGet:   (name, file) => req('GET', `/skills/${encodeURIComponent(name)}/files/${file}`),
  skillUsage:     (name) => req('GET', `/skills/${encodeURIComponent(name)}/usage`),
  createSkill:    (body) => req('POST', '/skills', body),
  deleteSkill:    (name) => req('DELETE', `/skills/${encodeURIComponent(name)}`),
  uploadSkill:    async (file) => {
    const fd = new FormData(); fd.append('file', file)
    const res = await fetch(BASE + '/skills/upload', { method: 'POST', headers: headers(), body: fd })
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || res.statusText)
    return res.json()
  },
  agentPrompt:    () => req('GET', '/agent/prompt'),
  llmUsageList:   (limit) => req('GET', `/llm/usage/list?limit=${limit || 100}`),
  workspaceList:  () => req('GET', '/workspace'),
  workspaceUpload: async (fd) => {
    const res = await fetch(BASE + '/workspace', { method: 'POST', headers: headers(), body: fd })
    if (!res.ok) throw new Error('upload failed: ' + res.status)
    return res.json()
  },
  workspaceDelete:(name) => req('DELETE', `/workspace/${encodeURIComponent(name)}`),
  notifyGet:      () => req('GET', '/notify/settings'),
  notifyPut:      (body) => req('PUT', '/notify/settings', body),
  notifyTest:     () => req('POST', '/notify/test', {}),
  systemLogs:     (limit) => req('GET', `/system/logs?limit=${limit || 200}`),
  syncScopeSentry:(body) => req('POST', '/assets/sync/scopesentry', body),
  autopilot:      (body) => req('POST', '/agent/autopilot', body),
  listMCP:        () => req('GET', '/mcp'),
  createMCP:      (body) => req('POST', '/mcp', body),
  deleteMCP:      (id) => req('DELETE', `/mcp/${id}`),
  listApprovals:  (pending) => req('GET', `/approvals${pending ? '?pending=1' : ''}`),
  decideApproval: (id, decision) => req('POST', `/approvals/${id}/decide`, { decision }),
  sideAsk:        (runId, question) => req('POST', `/runs/${runId}/ask`, { run_id: runId, question }),

  // Asset graph + companies
  listCompanies:  () => req('GET', '/companies'),
  createCompany:  (body) => req('POST', '/companies', body),
  graphAssets:    (params = {}) => req('GET', `/graph/assets?${new URLSearchParams(params)}`),
  insertAsset:    (body) => req('POST', '/graph/assets', body),
  deleteAsset:    (id) => req('DELETE', `/graph/assets/${id}`),

  // Traffic capture
  listTraffic:    (params = {}) => req('GET', `/traffic?${new URLSearchParams(params)}`),
  getTraffic:     (id) => req('GET', `/traffic/${id}`),
  bindTraffic:    (body) => req('POST', '/traffic/bind', body),
  systemVersion:  () => req('GET', '/system/version'),
  updateCheck:    () => req('GET', '/system/update/check'),
  selfUpdate:     () => req('POST', '/system/update'),
  captureToggle:  (enabled) => req('POST', '/capture/toggle', { enabled }),
  listRules:      () => req('GET', '/traffic/rules'),
  createRule:     (body) => req('POST', '/traffic/rules', body),
  deleteRule:     (id) => req('DELETE', `/traffic/rules/${id}`),

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
  reconBrief: (id) => req('GET', `/runs/${id}/recon-brief`),  // bridge: compile recon surface for a Task
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
  // attack-surface graph (recon-graph.py over the run workspace)
  genGraph: (runId) => req('POST', `/runs/${runId}/graph`),
  graphUrl: (runId) => `${BASE}/runs/${runId}/files/recon-graph.html?t=${Date.now()}`,

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
  // custom tools (agent-callable)
  listCustomTools: () => req('GET', '/tools/custom'),
  saveCustomTool:  (body) => req('POST', '/tools/custom', body),
  deleteCustomTool:(key) => req('DELETE', `/tools/custom/${encodeURIComponent(key)}`),
  testCustomTool:  (body) => req('POST', '/tools/custom/test', body),

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
  checkKeys:    () => req('GET', '/keys/check'),  // live-validate configured keys
  getKeysStats: () => req('GET', '/keys/stats'),
  getEnvStatus: () => req('GET', '/keys/env-status'),
  setKey:       (provider, value) => req('PUT', `/keys/${provider}`, { value }),
  deleteKey:    (provider) => req('DELETE', `/keys/${provider}`),

  // System (danger zone: reset DB + wipe run workspaces)
  getSystemUsage: () => req('GET', '/system/usage'),
  resetSystem:    (scope, confirm) => req('POST', '/system/reset', { scope, confirm }),

  // Autonomous Tasks (exploration engine)
  listTasks:     (status) => req('GET', `/tasks${status ? `?status=${status}` : ''}`),
  createTask:    (body) => req('POST', '/tasks', body),
  getTask:       (id) => req('GET', `/tasks/${id}`),
  deleteTask:    (id) => req('DELETE', `/tasks/${id}`),
  startTask:     (id) => req('POST', `/tasks/${id}/start`),
  pauseTask:     (id) => req('POST', `/tasks/${id}/pause`),
  stopTask:      (id) => req('POST', `/tasks/${id}/stop`),
  taskGraph:     (id) => req('GET', `/tasks/${id}/graph`),
  taskActivity:  (id, limit = 200) => req('GET', `/tasks/${id}/activity?limit=${limit}`),
  taskCoverage:  (id) => req('GET', `/tasks/${id}/coverage`),
  listRetests:   (fid) => req('GET', `/findings/${fid}/retests`),
  startRetest:   (fid, body = {}) => req('POST', `/findings/${fid}/retest`, body),
  taskMessage:   (id, text) => req('POST', `/tasks/${id}/message`, { text }),
  taskQuestions: (id) => req('GET', `/tasks/${id}/questions`),
  pendingQuestions: () => req('GET', '/questions/pending'),
  answerQuestion: (qid, answer) => req('POST', `/questions/${qid}/answer`, { answer }),
  skipQuestion:   (qid) => req('POST', `/questions/${qid}/skip`),

  // Agent role configs (goals/planner/worker/mainagent/retester)
  agentConfigs:   () => req('GET', '/agent-configs'),
  updateAgentConfig: (role, body) => req('PATCH', `/agent-configs/${role}`, body),

  // Task categories / templates / archive (ScopeWeaver parity)
  listTasksArchived: () => req('GET', '/tasks?archived=1'),
  archiveTask:    (id) => req('POST', `/tasks/${id}/archive`),
  restoreTask:    (id) => req('POST', `/tasks/${id}/restore`),
  setTaskCategory:(id, categoryId) => req('PATCH', `/tasks/${id}/category`, { category_id: categoryId }),
  listCategories: () => req('GET', '/task-categories'),
  createCategory: (name, color) => req('POST', '/task-categories', { name, color }),
  deleteCategory: (id) => req('DELETE', `/task-categories/${id}`),
  listTemplates:  () => req('GET', '/task-templates'),
  createTemplate: (body) => req('POST', '/task-templates', body),
  deleteTemplate: (id) => req('DELETE', `/task-templates/${id}`),
  launchTemplate: (id, autostart = true) => req('POST', `/task-templates/${id}/launch`, { autostart }),

  // LLM network setting + Ollama + update rollback + approval detail
  getLocalLLM:    () => req('GET', '/settings/local-llm'),
  setLocalLLM:    (enabled) => req('PUT', '/settings/local-llm', { enabled }),
  ollamaModels:   (baseUrl) => req('GET', `/ollama/models${baseUrl ? `?base_url=${encodeURIComponent(baseUrl)}` : ''}`),
  approvalDetail: (id) => req('GET', `/approvals/${id}`),
  updateRollback: () => req('POST', '/system/update/rollback'),
}

export function wsUrl(runId) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  const token = getToken()
  const qs = token ? `?token=${encodeURIComponent(token)}` : ''
  return `${proto}://${location.host}/ws/runs/${runId}${qs}`
}

export function wsTaskUrl(taskId) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  const token = getToken()
  const qs = token ? `?token=${encodeURIComponent(token)}` : ''
  return `${proto}://${location.host}/ws/tasks/${taskId}${qs}`
}
