import React, { useEffect, useRef, useState, useCallback } from 'react'
import { api } from '../api.js'
import { timeAgo } from '../utils.js'

const SUGGESTIONS = [
  'Recon example.com — register the target and run the full pipeline',
  'Summarize the latest findings by severity',
  'Check scope for sub.example.com, then launch 02-js-secrets',
]

const fmtTok = n => n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e3 ? (n / 1e3).toFixed(1) + 'k' : String(n)

function Icon({ d, size = 14 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor"
         strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {d}
    </svg>
  )
}
const I = {
  spark: <path d="M8 1.5 9.5 6.5 14.5 8 9.5 9.5 8 14.5 6.5 9.5 1.5 8 6.5 6.5z" />,
  plus: <path d="M8 3v10M3 8h10" />,
  gear: <><circle cx="8" cy="8" r="2.2" /><path d="M8 1.8v2M8 12.2v2M1.8 8h2M12.2 8h2M3.6 3.6l1.4 1.4M11 11l1.4 1.4M12.4 3.6 11 5M5 11l-1.4 1.4" /></>,
  send: <path d="M2 8 14 2.5 9.5 14 7.8 9.2z" />,
  trash: <path d="M2.5 4h11M6.5 4V2.5h3V4M4 4l.7 9h6.6L12 4M6.7 7v3.5M9.3 7v3.5" />,
  pin: <path d="M6 2h4l-.5 4 2 2v1.5H5V8l2-2z M8 10.5V14" />,
  edit: <path d="M11 2.5 13.5 5 6 12.5 3 13l.5-3z" />,
}

export default function Agent() {
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [convId, setConvId] = useState(null)
  const [convs, setConvs] = useState([])
  const [profiles, setProfiles] = useState([])
  const [profileId, setProfileId] = useState(null)
  const [showConfig, setShowConfig] = useState(false)
  const [err, setErr] = useState('')
  const [formErr, setFormErr] = useState('')
  const [saving, setSaving] = useState(false)
  const [form, setForm] = useState({ name: 'GLM', base_url: 'https://api.z.ai/api/coding/paas/v4', api_key: '', model: 'glm-4.7' })
  const [lastTokens, setLastTokens] = useState(null)
  const [rules, setRules] = useState([])
  const [audit, setAudit] = useState([])
  const [showGovernance, setShowGovernance] = useState(false)
  // conversation management + mentions (ScopeWeaver parity)
  const [editingId, setEditingId] = useState(null)
  const [editTitle, setEditTitle] = useState('')
  const [selected, setSelected] = useState([])
  const [mentions, setMentions] = useState([])
  const [mentionOpen, setMentionOpen] = useState(false)
  const [collapsedGroups, setCollapsedGroups] = useState({})
  const [newAgentKey, setNewAgentKey] = useState('recon-agent')
  // attachments, stop, send-mode, side-questions, approvals, todo (ScopeWeaver chat parity)
  const [attachments, setAttachments] = useState([])
  const [uploading, setUploading] = useState(false)
  const [sendMode, setSendMode] = useState(() => localStorage.getItem('k1z-send-mode') || 'enter')
  const [pendingQ, setPendingQ] = useState([])
  const [approvals, setApprovals] = useState([])
  const [showTodo, setShowTodo] = useState(false)
  const [runningTasks, setRunningTasks] = useState([])
  const fileRef = useRef(null)

  useEffect(() => { localStorage.setItem('k1z-send-mode', sendMode) }, [sendMode])
  useEffect(() => {
    const poll = () => {
      api.pendingQuestions().then(r => setPendingQ(r.items || [])).catch(() => {})
      api.listApprovals(true).then(a => setApprovals(Array.isArray(a) ? a : (a.items || []))).catch(() => {})
    }
    poll(); const t = setInterval(poll, 4000); return () => clearInterval(t)
  }, [])

  async function pickFiles(e) {
    const files = [...(e.target.files || [])]
    if (!files.length) return
    setUploading(true)
    try {
      for (const f of files) { const r = await api.chatUpload(f); setAttachments(a => [...a, { path: r.path, name: r.name, size: r.size }]) }
    } catch (e2) { setErr(e2.message) } finally { setUploading(false); if (fileRef.current) fileRef.current.value = '' }
  }
  const removeAttachment = p => setAttachments(a => a.filter(x => x.path !== p))
  async function stopGen() { if (convId) { try { await api.stopChat(convId) } catch {} } }
  async function openTodo() {
    setShowTodo(v => !v)
    try {
      const r = await api.listTasks()
      const running = (r.items || []).filter(t => t.running || t.status === 'running')
      const full = await Promise.all(running.map(t => api.getTask(t.id).catch(() => null)))
      setRunningTasks(full.filter(Boolean))
    } catch {}
  }
  const submitOnKey = e => (sendMode === 'enter' ? (e.key === 'Enter' && !e.shiftKey) : (e.key === 'Enter' && (e.metaKey || e.ctrlKey)))

  const toggleSelect = (id, e) => { e.stopPropagation(); setSelected(s => s.includes(id) ? s.filter(x => x !== id) : [...s, id]) }
  async function togglePin(c, e) { e.stopPropagation(); try { await api.pinConv(c.id, !c.pinned); loadConvs() } catch {} }
  async function saveRename(id) { const t = editTitle.trim(); setEditingId(null); if (t) { try { await api.renameConv(id, t); loadConvs() } catch {} } }
  async function batchDelete() {
    if (!selected.length || !confirm(`Delete ${selected.length} conversation(s)?`)) return
    try { await api.deleteConvsBatch(selected); if (selected.includes(convId)) newChat(); setSelected([]); loadConvs() } catch {}
  }
  // @mention lookup: query when the token after the last "@" changes
  async function onInputChange(v) {
    setInput(v)
    const m = /(^|\s)@([\w.\-:/]*)$/.exec(v)
    if (m) {
      try { const r = await api.chatMentions(m[2]); setMentions(r.items || []); setMentionOpen(true) } catch { setMentionOpen(false) }
    } else setMentionOpen(false)
  }
  function insertMention(item) {
    setInput(v => v.replace(/(^|\s)@([\w.\-:/]*)$/, `$1@${item.label} `))
    setMentionOpen(false)
  }

  const loadGov = useCallback(async () => {
    try { setRules(await api.agentRules()) } catch {}
    try { setAudit(await api.agentAudit(30)) } catch {}
  }, [])
  useEffect(() => { loadGov() }, [loadGov])

  async function addRule(e) {
    e.preventDefault()
    const tool = e.target.elements.tool.value.trim()
    const action = e.target.elements.action.value
    if (!tool) return
    try { await api.createAgentRule({ tool_pattern: tool, input_pattern: e.target.elements.input.value.trim(), action }); e.target.reset(); loadGov() } catch {}
  }

  async function removeRule(id) {
    try { await api.deleteAgentRule(id); loadGov() } catch {}
  }
  const bottomRef = useRef(null)

  const loadConvs = useCallback(async () => {
    try { setConvs(await api.listConvs()) } catch {}
  }, [])
  const loadProfiles = useCallback(async () => {
    try {
      const p = await api.listLLM()
      setProfiles(p)
      if (p.length && !profileId) setProfileId(p[0].id)
    } catch {}
  }, [profileId])

  useEffect(() => { loadConvs(); loadProfiles() }, []) // eslint-disable-line
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [messages, busy])

  async function openConv(id) {
    setConvId(id)
    setErr('')
    try { setMessages(await api.convMessages(id)) } catch (e) { setErr(e.message) }
  }

  function newChat() { setConvId(null); setMessages([]); setErr('') }

  async function removeConv(id, e) {
    e.stopPropagation()
    try {
      await api.deleteConv(id)
      if (convId === id) newChat()
      loadConvs()
    } catch {}
  }

  async function send(preset) {
    const text = (preset || input).trim()
    if (!text || busy) return
    const atts = attachments.map(a => a.path)
    setInput('')
    setMentionOpen(false)
    setMessages(m => [...m, { role: 'user', content: text, attachments: attachments.map(a => a.name) }])
    setBusy(true)
    setErr('')
    const body = { message: text }
    if (convId) body.conversation_id = convId
    else body.agent_key = newAgentKey
    if (profileId) body.profile_id = profileId
    if (atts.length) body.attachments = atts
    setAttachments([])
    // optimistic streaming assistant bubble
    setMessages(m => [...m, { role: 'assistant', content: '', streaming: true, tool_calls: [], activities: [] }])
    const setLast = (fn) => setMessages(m => { const c = [...m]; const i = c.length - 1; if (i >= 0 && c[i].role === 'assistant') c[i] = fn(c[i]); return c })
    try {
      await api.agentChatStream(body, ev => {
        switch (ev.event) {
          case 'start': if (ev.conversation_id) setConvId(ev.conversation_id); break
          case 'delta': setLast(a => ({ ...a, content: a.content + (ev.content || '') })); break
          case 'tool': setLast(a => ({ ...a, tool_calls: [...(a.tool_calls || []), ev.name],
            activities: [...(a.activities || []), { name: ev.name, args: ev.args || '', output: null }] })); break
          case 'tool_result': setLast(a => {
            const acts = [...(a.activities || [])]
            for (let j = acts.length - 1; j >= 0; j--) { if (acts[j].name === ev.name && acts[j].output == null) { acts[j] = { ...acts[j], output: ev.output || '' }; break } }
            return { ...a, activities: acts }
          }); break
          case 'done':
            if (ev.conversation_id) setConvId(ev.conversation_id)
            if (ev.tokens) setLastTokens(ev.tokens)
            setLast(a => ({ ...a, streaming: false, content: ev.reply || a.content, stopped: ev.stopped }))
            loadConvs()
            break
          case 'error':
            setErr(ev.error); setLast(a => ({ ...a, streaming: false, error: ev.error }))
            break
        }
      })
    } catch (e) {
      setErr(e.message)
      setLast(a => ({ ...a, streaming: false, error: e.message }))
    }
    setBusy(false)
  }

  async function startAutopilot() {
    const goal = input.trim() || prompt('Engagement goal, e.g. Full recon acme.com and triage findings');
    if (!goal) return
    setBusy(true)
    setErr('')
    try {
      await api.autopilot({ goal })
      setMessages(m => [...m, { role: 'user', content: `🚀 Autopilot: ${goal}` },
        { role: 'assistant', content: 'Autopilot started — follow it in the Conversations list (auto-updating). The plan → execute → analyze steps are logged to the "autopilot: …" conversation.' }])
      setInput('')
      loadConvs()
    } catch (e2) { setErr(e2.message) } finally { setBusy(false) }
  }

  async function createProfile(e) {
    e.preventDefault()
    setFormErr('')
    setSaving(true)
    try {
      await api.createLLM(form)
      setForm({ ...form, api_key: '' })
      setShowConfig(false)
      loadProfiles()
    } catch (e2) { setFormErr(e2.message) } finally { setSaving(false) }
  }

  async function removeProfile() {
    if (!profileId) return
    if (!confirm('Delete this LLM profile?')) return
    try {
      await api.deleteLLM(profileId)
      setProfileId(null)
      loadProfiles()
    } catch (e) { setFormErr(e.message) }
  }

  const noProfile = profiles.length === 0

  return (
    <div className="fade-in p-6">
      {/* page header */}
      <div className="flex items-center gap-2.5 mb-4">
        <span className="p-2 rounded-lg" style={{ background: 'var(--surface-3)', color: 'var(--accent)' }}>
          <Icon d={I.spark} size={17} />
        </span>
        <div>
          <h2 className="text-[15px] font-bold leading-tight">AI Agent</h2>
          <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
            GLM-driven operator — launches scans, triages findings, maintains the graph
          </p>
        </div>
      </div>

      <div className="grid gap-4" style={{ gridTemplateColumns: '240px 1fr', height: 'calc(100vh - 150px)' }}>
        {/* ── sidebar ── */}
        <div className="flex flex-col gap-2.5 min-w-0">
          <button className="btn btn-primary flex items-center justify-center gap-1.5" onClick={newChat}>
            <Icon d={I.plus} /> New chat
          </button>

          <div className="card flex-1 overflow-y-auto" style={{ padding: 0 }}>
            <div className="card-header text-[10px]" style={{ padding: '10px 12px' }}>
              Conversations
              {selected.length > 0 && (
                <button className="btn btn-danger text-[9.5px] px-2 py-0.5 ml-auto" onClick={batchDelete}>
                  Delete {selected.length}
                </button>
              )}
            </div>
            {(() => {
              const groups = {}
              for (const c of convs) { const k = c.agent_key || 'recon-agent'; (groups[k] = groups[k] || []).push(c) }
              const keys = Object.keys(groups)
              return keys.map(gk => {
                const collapsed = collapsedGroups[gk]
                return (
                  <div key={gk}>
                    {keys.length > 1 && (
                      <div className="px-3 py-1.5 flex items-center gap-1.5 cursor-pointer border-b text-[9px] uppercase tracking-wider font-bold"
                           style={{ borderColor: 'var(--border)', color: 'var(--text-3)', background: 'var(--bg-soft)' }}
                           onClick={() => setCollapsedGroups(s => ({ ...s, [gk]: !s[gk] }))}>
                        <span>{collapsed ? '▸' : '▾'}</span><span className="truncate">{gk}</span>
                        <span className="ml-auto font-mono">{groups[gk].length}</span>
                      </div>
                    )}
                    {!collapsed && groups[gk].map(c => (
                      <div key={c.id} onClick={() => openConv(c.id)}
                           className="group flex items-center gap-2 px-3 py-2 cursor-pointer border-b transition-colors"
                           style={{ borderColor: 'var(--border)', background: convId === c.id ? 'var(--surface-3)' : selected.includes(c.id) ? 'var(--surface-2)' : 'transparent' }}>
                        <input type="checkbox" checked={selected.includes(c.id)} onClick={e => toggleSelect(c.id, e)} onChange={() => {}}
                               className="opacity-0 group-hover:opacity-100 checked:opacity-100" style={{ accentColor: 'var(--accent)' }} />
                        <div className="flex-1 min-w-0">
                          {editingId === c.id ? (
                            <input autoFocus className="input text-[11.5px] py-0.5" value={editTitle} onClick={e => e.stopPropagation()}
                                   onChange={e => setEditTitle(e.target.value)} onBlur={() => saveRename(c.id)}
                                   onKeyDown={e => { if (e.key === 'Enter') saveRename(c.id); if (e.key === 'Escape') setEditingId(null) }} />
                          ) : (
                            <div className="text-[11.5px] font-medium truncate flex items-center gap-1" style={{ color: 'var(--text)' }}>
                              {c.pinned && <span style={{ color: 'var(--amber)' }}>📌</span>}{c.title}
                            </div>
                          )}
                          <div className="text-[9.5px] flex items-center gap-1.5" style={{ color: 'var(--text-3)' }}>
                            {timeAgo(c.updated_at)}{c.total_tokens > 0 && <span className="font-mono">· {fmtTok(c.total_tokens)} tok</span>}
                          </div>
                        </div>
                        <div className="flex items-center opacity-0 group-hover:opacity-100 transition-opacity">
                          <button className="p-1 rounded" style={{ color: c.pinned ? 'var(--amber)' : 'var(--text-3)' }}
                                  onClick={e => togglePin(c, e)} title={c.pinned ? 'Unpin' : 'Pin'}><Icon d={I.pin} size={12} /></button>
                          <button className="p-1 rounded" style={{ color: 'var(--text-3)' }}
                                  onClick={e => { e.stopPropagation(); setEditingId(c.id); setEditTitle(c.title) }} title="Rename"><Icon d={I.edit} size={12} /></button>
                          <button className="p-1 rounded" style={{ color: 'var(--text-3)' }} onClick={e => removeConv(c.id, e)} title="Delete"><Icon d={I.trash} size={12} /></button>
                        </div>
                      </div>
                    ))}
                  </div>
                )
              })
            })()}
            {!convs.length && (
              <div className="px-3 py-4 text-[11px]" style={{ color: 'var(--text-3)' }}>No conversations yet</div>
            )}
          </div>

          {/* profile picker */}
          <div className="flex gap-1.5">
            <select className="input text-[11px] flex-1" value={profileId || ''} onChange={e => setProfileId(+e.target.value)}>
              {profiles.map(p => <option key={p.id} value={p.id}>{p.name} · {p.model}</option>)}
            </select>
            {profiles.length > 0 && (
              <button className="btn px-2" onClick={removeProfile} title="Delete profile">
                <Icon d={I.trash} size={12} />
              </button>
            )}
          </div>
          <button className="btn flex items-center justify-center gap-1.5" onClick={() => { setShowConfig(v => !v); setFormErr('') }}>
            <Icon d={I.gear} /> LLM profile
          </button>
          <button className="btn btn-accent flex items-center justify-center gap-1.5" onClick={startAutopilot} disabled={busy || !profiles.length}>
            <Icon d={I.spark} /> Autopilot
          </button>
          <button className="btn flex items-center justify-center gap-1.5" onClick={() => { setShowGovernance(v => !v); loadGov() }}>
            <Icon d={I.gear} /> Governance
          </button>
          {showGovernance && (
            <div className="card p-3 flex flex-col gap-2.5 fade-in overflow-y-auto" style={{ maxHeight: 340 }}>
              <p className="text-[9.5px] uppercase tracking-wider font-bold" style={{ color: 'var(--text-2)' }}>
                Agent rules — allow / deny / ask tool-calls
              </p>
              <form onSubmit={addRule} className="flex flex-col gap-1.5">
                <input name="tool" className="input text-[10.5px] font-mono" placeholder="tool, e.g. cancel_run (re: for regex)" />
                <input name="input" className="input text-[10.5px] font-mono" placeholder="input contains… (empty = any input)" />
                <div className="flex gap-1.5">
                  <select name="action" className="input text-[10.5px] flex-1">
                    <option value="ask">ask — await approval</option>
                    <option value="deny">deny — block</option>
                    <option value="allow">allow — pass through</option>
                  </select>
                  <button className="btn btn-accent text-[10.5px]" type="submit">Add</button>
                </div>
              </form>
              {rules.map(r => (
                <div key={r.id} className="flex items-center gap-1.5 text-[10px] font-mono">
                  <span className="badge" style={{
                    background: r.action === 'deny' ? 'rgba(248,81,73,.12)' : r.action === 'ask' ? 'rgba(240,180,41,.12)' : 'rgba(63,185,80,.12)',
                    color: r.action === 'deny' ? 'var(--red)' : r.action === 'ask' ? 'var(--amber)' : 'var(--green)' }}>
                    {r.action}
                  </span>
                  <span className="truncate flex-1" title={r.input_pattern}>{r.tool_pattern}{r.input_pattern ? ` · ${r.input_pattern}` : ''}</span>
                  <button className="opacity-60 hover:opacity-100" onClick={() => removeRule(r.id)}>✕</button>
                </div>
              ))}
              <p className="text-[9.5px] uppercase tracking-wider font-bold mt-1" style={{ color: 'var(--text-2)' }}>
                Audit — recent tool-calls
              </p>
              <div className="flex flex-col gap-0.5">
                {audit.map(a => (
                  <div key={a.id} className="text-[9.5px] font-mono truncate" style={{ color: a.blocked ? 'var(--red)' : 'var(--text-3)' }}>
                    {a.blocked ? '⛔' : '⚙'} {a.tool} {String(a.args || '').slice(0, 46)}
                  </div>
                ))}
                {!audit.length && <div className="text-[10px]" style={{ color: 'var(--text-3)' }}>no tool-calls yet</div>}
              </div>
            </div>
          )}

          {showConfig && (
            <form onSubmit={createProfile} className="card flex flex-col gap-2 p-3 fade-in">
              <div>
                <label className="label">Name</label>
                <input className="input" value={form.name} required onChange={e => setForm({ ...form, name: e.target.value })} />
              </div>
              <div>
                <label className="label">Preset</label>
                <select className="input text-[11px]" value={form.base_url}
                        onChange={e => setForm({ ...form, base_url: e.target.value, model: e.target.selectedOptions[0].dataset.model || form.model })}>
                  <option value="https://api.z.ai/api/coding/paas/v4" data-model="glm-4.7">Z.ai Coding Plan (OpenAI) — glm-4.7</option>
                  <option value="https://api.z.ai/api/paas/v4" data-model="glm-4.7">Z.ai General API (balance) — glm-4.7</option>
                  <option value="https://api.z.ai/api/paas/v4" data-model="glm-4.5-flash">Z.ai Free — glm-4.5-flash</option>
                  <option value="https://open.bigmodel.cn/api/paas/v4" data-model="glm-4.6">BigModel (CN) — glm-4.6</option>
                  <option value="">Custom…</option>
                </select>
              </div>
              <div>
                <label className="label">Base URL</label>
                <input className="input font-mono text-[10.5px]" value={form.base_url} onChange={e => setForm({ ...form, base_url: e.target.value })} />
              </div>
              <div>
                <label className="label">API key</label>
                <input className="input font-mono text-[10.5px]" type="password" required value={form.api_key}
                       onChange={e => setForm({ ...form, api_key: e.target.value })} />
              </div>
              <div>
                <label className="label">Model</label>
                <input className="input font-mono text-[10.5px]" value={form.model} onChange={e => setForm({ ...form, model: e.target.value })} />
              </div>
              {formErr && (
                <p className="text-[10.5px]" style={{ color: 'var(--red)' }}>⚠ {formErr}</p>
              )}
              <button className="btn btn-primary" type="submit" disabled={saving}>
                {saving ? 'Saving…' : 'Save profile'}
              </button>
            </form>
          )}
        </div>

        {/* ── chat ── */}
        <div className="card flex flex-col min-w-0" style={{ padding: 0 }}>
          {/* chat toolbar: todo popover + live indicators */}
          <div className="flex items-center gap-2 px-3 py-2 border-b relative" style={{ borderColor: 'var(--border)' }}>
            <span className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-3)' }}>Chat</span>
            <div className="ml-auto flex items-center gap-1.5">
              {pendingQ.length > 0 && <span className="badge text-[9px]" style={{ background: 'rgba(242,201,76,.16)', color: 'var(--amber)' }}>❓ {pendingQ.length}</span>}
              {approvals.length > 0 && <span className="badge text-[9px]" style={{ background: 'rgba(255,92,87,.16)', color: 'var(--red)' }}>⚑ {approvals.length}</span>}
              <button className="btn btn-ghost text-[10px] px-2 py-1" onClick={openTodo}>☰ Todos</button>
            </div>
            {showTodo && (
              <div className="absolute top-full right-2 mt-1 w-96 max-h-[50vh] overflow-auto rounded-md z-30 card p-3" style={{ boxShadow: 'var(--shadow-2)' }}>
                <div className="text-[10px] uppercase tracking-wider font-semibold mb-2" style={{ color: 'var(--text-3)' }}>Running task todolists</div>
                {!runningTasks.length && <div className="text-[11px]" style={{ color: 'var(--text-3)' }}>No running tasks.</div>}
                {runningTasks.map(t => (
                  <div key={t.id} className="mb-3">
                    <div className="text-[11px] font-semibold truncate">#{t.id} {t.name || t.goal}</div>
                    <pre className="text-[10px] whitespace-pre-wrap font-mono mt-1" style={{ color: 'var(--text-2)' }}>{t.todolist || '(no todolist yet)'}</pre>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* pending side-questions (human-in-the-loop, surfaced in chat) */}
          {pendingQ.map(q => (
            <ChatQuestion key={q.id} q={q} onAnswer={(id, a) => api.answerQuestion(id, a).then(() => setPendingQ(p => p.filter(x => x.id !== id)))}
                          onSkip={id => api.skipQuestion(id).then(() => setPendingQ(p => p.filter(x => x.id !== id)))} />
          ))}
          {/* pending tool-call approvals (approval execution focus) */}
          {approvals.map(a => (
            <div key={a.id} className="px-4 py-2.5 border-b flex items-center gap-2" style={{ borderColor: 'var(--red)', background: 'rgba(255,92,87,.06)' }}>
              <span className="badge text-[9px]" style={{ background: 'rgba(255,92,87,.16)', color: 'var(--red)' }}>approval</span>
              <span className="text-[11px] font-mono truncate flex-1">{a.tool || a.method} {a.args || `${a.host || ''}${a.path || ''}`}</span>
              <button className="btn btn-primary text-[10px] px-2 py-1" onClick={() => api.decideApproval(a.id, 'approve').then(() => setApprovals(x => x.filter(y => y.id !== a.id)))}>Approve</button>
              <button className="btn btn-danger text-[10px] px-2 py-1" onClick={() => api.decideApproval(a.id, 'deny').then(() => setApprovals(x => x.filter(y => y.id !== a.id)))}>Deny</button>
            </div>
          ))}

          <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-3">
            {noProfile && (
              <div className="card p-4 text-[12px] leading-relaxed" style={{ borderColor: 'var(--accent)' }}>
                <p className="font-semibold mb-1.5" style={{ color: 'var(--accent)' }}>⚙ No LLM configured</p>
                <p style={{ color: 'var(--text-2)' }}>
                  Create a profile in the left sidebar: Base URL <code className="font-mono">https://api.z.ai/api/paas/v4</code>,
                  model <code className="font-mono">glm-4.7</code>, API key from Z.ai — then start chatting.
                </p>
              </div>
            )}
            {!messages.length && !noProfile && (
              <div className="flex flex-col gap-2 items-start py-6 px-2">
                <p className="text-[12px] mb-1" style={{ color: 'var(--text-3)' }}>Try one of the quick commands:</p>
                {SUGGESTIONS.map(s => (
                  <button key={s} className="btn text-left text-[11.5px]" style={{ maxWidth: 480 }}
                          onClick={() => send(s)}>{s}</button>
                ))}
              </div>
            )}
            {messages.map((m, i) => m.role === 'user' ? (
              <div key={i} className="self-end max-w-[76%] rounded-xl px-3.5 py-2.5 text-[12.5px] whitespace-pre-wrap"
                   style={{ background: 'rgba(88,166,255,.12)', border: '1px solid rgba(88,166,255,.35)' }}>
                {m.content}
                {m.attachments?.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-1.5">
                    {m.attachments.map((n, k) => <span key={k} className="text-[9.5px] font-mono px-1.5 py-0.5 rounded" style={{ background: 'var(--surface-3)', color: 'var(--text-2)' }}>📎 {n}</span>)}
                  </div>
                )}
              </div>
            ) : (
              <div key={i} className="self-start max-w-[80%] rounded-xl px-3.5 py-2.5 text-[12.5px] whitespace-pre-wrap"
                   style={{ background: 'var(--surface)', border: '1px solid var(--border)' }}>
                {(m.activities?.length > 0) && <ToolActivities acts={m.activities} />}
                <Markdown text={m.content} />
                {m.streaming && <span className="inline-block w-[7px] h-[13px] ml-0.5 align-middle animate-pulse" style={{ background: 'var(--accent)' }} />}
                {m.error && <span style={{ color: 'var(--red)' }}>⚠ {m.error}</span>}
                {m.stopped && !m.content && <span style={{ color: 'var(--text-3)' }}>(stopped)</span>}
                {/* fallback chips for non-streamed history messages */}
                {!m.activities?.length && m.tool_calls?.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 mt-2">
                    {m.tool_calls.map((t, j) => (
                      <span key={j} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[9.5px] font-mono"
                            style={{ background: 'rgba(63,185,80,.12)', color: 'var(--green)' }}>⚙ {t}</span>
                    ))}
                  </div>
                )}
              </div>
            ))}
            {busy && !messages[messages.length - 1]?.content && (
              <div className="self-start flex items-center gap-1.5 text-[11px] px-3 py-2 rounded-xl"
                   style={{ background: 'var(--surface)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
                <span className="badge badge-running" style={{ padding: '2px 8px' }}>thinking</span>
                agent is calling tools / composing the reply…
              </div>
            )}
            {err && !busy && !messages.some(m => m.error) && (
              <div className="self-start text-[11px] px-3 py-2 rounded-lg" style={{ color: 'var(--red)', background: 'rgba(248,81,73,.08)' }}>
                ⚠ {err}
              </div>
            )}
            <div ref={bottomRef} />
          </div>

          <div className="flex gap-2 p-3 border-t relative" style={{ borderColor: 'var(--border)' }}>
            {/* @mention dropdown */}
            {mentionOpen && mentions.length > 0 && (
              <div className="absolute bottom-full left-3 mb-1 w-80 rounded-md overflow-hidden z-20 card" style={{ boxShadow: 'var(--shadow-2)' }}>
                {mentions.map(m => (
                  <div key={m.kind + m.id} className="px-3 py-1.5 cursor-pointer text-[11px] flex items-center gap-2 hover:bg-[var(--surface-2)] border-b"
                       style={{ borderColor: 'var(--border)' }} onMouseDown={e => { e.preventDefault(); insertMention(m) }}>
                    <span className="badge text-[8.5px] font-mono" style={{ background: 'var(--surface-2)', color: m.kind === 'finding' ? 'var(--red)' : m.kind === 'task' ? 'var(--amber)' : 'var(--accent)' }}>{m.kind}</span>
                    <span className="font-mono truncate flex-1">{m.label}</span>
                    <span className="text-[9px] truncate" style={{ color: 'var(--text-3)' }}>{m.sub}</span>
                  </div>
                ))}
              </div>
            )}
            {/* attachment chips */}
            {attachments.length > 0 && (
              <div className="absolute bottom-full left-3 right-3 mb-1 flex flex-wrap gap-1.5 z-10">
                {attachments.map(a => (
                  <span key={a.path} className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-[10px] font-mono"
                        style={{ background: 'var(--surface-3)', color: 'var(--text-2)' }}>
                    📎 {a.name} <button className="ml-0.5" style={{ color: 'var(--text-3)' }} onClick={() => removeAttachment(a.path)}>✕</button>
                  </span>
                ))}
              </div>
            )}
            <input ref={fileRef} type="file" multiple className="hidden" onChange={pickFiles} />
            <button className="btn self-stretch px-2.5" title="Attach files" onClick={() => fileRef.current?.click()} disabled={uploading}>
              {uploading ? '…' : '📎'}
            </button>
            <textarea className="input flex-1 resize-none font-[13px]" rows={2} value={input}
                      onChange={e => onInputChange(e.target.value)}
                      onKeyDown={e => { if (e.key === 'Escape') setMentionOpen(false); if (submitOnKey(e) && !mentionOpen) { e.preventDefault(); send() } }}
                      placeholder={`Chat, or @mention an asset / finding / task…  (${sendMode === 'enter' ? 'Enter' : 'Ctrl+Enter'} to send)`} />
            {busy ? (
              <button className="btn btn-danger flex items-center gap-1.5 self-stretch px-4" onClick={stopGen} title="Stop generation">■ Stop</button>
            ) : (
              <button className="btn btn-primary flex items-center gap-1.5 self-stretch px-4" onClick={() => send()} disabled={!input.trim()}>
                <Icon d={I.send} /> Send
              </button>
            )}
          </div>
          {/* send-mode toggle */}
          <div className="flex items-center gap-2 px-3 pb-2 text-[9.5px]" style={{ color: 'var(--text-3)' }}>
            <span>Send with</span>
            <button className="font-mono hover:underline" style={{ color: 'var(--accent)' }}
                    onClick={() => setSendMode(m => m === 'enter' ? 'mod' : 'enter')}>
              {sendMode === 'enter' ? 'Enter (Shift+Enter = newline)' : 'Ctrl/⌘+Enter (Enter = newline)'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

function ChatQuestion({ q, onAnswer, onSkip }) {
  const [text, setText] = React.useState('')
  return (
    <div className="px-4 py-3 border-b" style={{ borderColor: 'var(--amber)', background: 'rgba(242,201,76,.06)' }}>
      <div className="flex items-center gap-2 mb-1.5">
        <span className="badge text-[9px] font-mono" style={{ background: 'rgba(242,201,76,.16)', color: 'var(--amber)' }}>❓ task #{q.exploration_id} asks</span>
        <span className="text-[9.5px] font-mono" style={{ color: 'var(--text-3)' }}>{q.worker}</span>
      </div>
      <div className="text-[12px] mb-2" style={{ color: 'var(--text)' }}>{q.question}</div>
      <div className="flex gap-2">
        <input className="input text-[11px]" placeholder="Your answer…" value={text}
               onChange={e => setText(e.target.value)}
               onKeyDown={e => { if (e.key === 'Enter' && text.trim()) onAnswer(q.id, text) }} />
        <button className="btn btn-primary text-[11px]" disabled={!text.trim()} onClick={() => onAnswer(q.id, text)}>Answer</button>
        <button className="btn btn-ghost text-[11px]" onClick={() => onSkip(q.id)}>Skip</button>
      </div>
    </div>
  )
}

// ToolActivities renders the merged tool-call transcript (name → args → output),
// each expandable — the ScopeWeaver transcript activity-merge.
function ToolActivities({ acts }) {
  const [open, setOpen] = React.useState({})
  return (
    <div className="flex flex-col gap-1 mb-2 rounded-lg overflow-hidden" style={{ border: '1px solid var(--border)' }}>
      <div className="px-2.5 py-1 text-[9.5px] font-semibold uppercase tracking-wider" style={{ background: 'var(--surface-2)', color: 'var(--text-3)' }}>
        🔧 {acts.length} tool {acts.length === 1 ? 'call' : 'calls'}
      </div>
      {acts.map((a, i) => {
        const o = open[i]
        return (
          <div key={i} className="px-2.5 py-1 border-t" style={{ borderColor: 'var(--border)' }}>
            <div className="flex items-center gap-1.5 cursor-pointer" onClick={() => setOpen(s => ({ ...s, [i]: !s[i] }))}>
              <span className="font-mono text-[10px]" style={{ color: a.output == null ? 'var(--amber)' : 'var(--green)' }}>
                {a.output == null ? '◐' : '⚙'} {a.name}
              </span>
              <span className="text-[9px] ml-auto" style={{ color: 'var(--text-3)' }}>{o ? '▴' : '▾'}</span>
            </div>
            {o && (
              <div className="mt-1 flex flex-col gap-1">
                {a.args && <pre className="m-0 whitespace-pre-wrap text-[9.5px] font-mono p-1.5 rounded" style={{ background: 'var(--bg-soft)', color: 'var(--text-2)' }}>args: {a.args}</pre>}
                {a.output != null && <pre className="m-0 whitespace-pre-wrap text-[9.5px] font-mono p-1.5 rounded" style={{ background: 'var(--bg-soft)', color: 'var(--text-2)' }}>{a.output || '(empty)'}</pre>}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

// Markdown is a tiny renderer: code fences, inline code, bold, and line breaks —
// enough to make the assistant transcript read like ScopeWeaver without a dep.
function Markdown({ text }) {
  if (!text) return null
  const parts = String(text).split(/```/)
  return (
    <div className="leading-relaxed">
      {parts.map((part, i) => i % 2 === 1
        ? <pre key={i} className="my-1.5 p-2 rounded-md overflow-auto text-[11px] font-mono" style={{ background: 'var(--bg-soft)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>{part.replace(/^[a-z]*\n/, '')}</pre>
        : <span key={i}>{renderInline(part)}</span>)}
    </div>
  )
}
function renderInline(s) {
  // split on `code` and **bold**, keep delimiters
  const tokens = s.split(/(`[^`]+`|\*\*[^*]+\*\*)/g)
  return tokens.map((t, i) => {
    if (t.startsWith('`') && t.endsWith('`')) return <code key={i} className="px-1 rounded text-[11px] font-mono" style={{ background: 'var(--surface-2)', color: 'var(--accent)' }}>{t.slice(1, -1)}</code>
    if (t.startsWith('**') && t.endsWith('**')) return <strong key={i}>{t.slice(2, -2)}</strong>
    return <span key={i}>{t}</span>
  })
}
