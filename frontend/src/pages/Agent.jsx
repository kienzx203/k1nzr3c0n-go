import React, { useEffect, useRef, useState, useCallback } from 'react'
import { api } from '../api.js'
import { timeAgo } from '../utils.js'

const SUGGESTIONS = [
  'Recon example.com — register the target and run the full pipeline',
  'Summarize the latest findings by severity',
  'Check scope for sub.example.com, then launch 02-js-secrets',
]

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
    setInput('')
    setMessages(m => [...m, { role: 'user', content: text }])
    setBusy(true)
    setErr('')
    try {
      const body = { message: text }
      if (convId) body.conversation_id = convId
      if (profileId) body.profile_id = profileId
      const data = await api.agentChat(body)
      setConvId(data.conversation_id)
      setLastTokens(data.tokens)
      setMessages(m => [...m, { role: 'assistant', content: data.reply, tool_calls: data.tool_calls }])
      loadConvs()
    } catch (e) {
      setErr(e.message)
      setMessages(m => [...m, { role: 'assistant', content: '', error: e.message }])
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
            <div className="card-header text-[10px]" style={{ padding: '10px 12px' }}>Conversations</div>
            {convs.map(c => (
              <div key={c.id} onClick={() => openConv(c.id)}
                   className="group flex items-center gap-2 px-3 py-2 cursor-pointer border-b transition-colors"
                   style={{
                     borderColor: 'var(--border)',
                     background: convId === c.id ? 'var(--surface-3)' : 'transparent',
                   }}
                   onMouseEnter={e => { if (convId !== c.id) e.currentTarget.style.background = 'var(--surface-2)' }}
                   onMouseLeave={e => { if (convId !== c.id) e.currentTarget.style.background = 'transparent' }}>
                <div className="flex-1 min-w-0">
                  <div className="text-[11.5px] font-medium truncate" style={{ color: 'var(--text)' }}>{c.title}</div>
                  <div className="text-[9.5px]" style={{ color: 'var(--text-3)' }}>{timeAgo(c.updated_at)}</div>
                </div>
                <button className="opacity-0 group-hover:opacity-100 transition-opacity p-1 rounded"
                        style={{ color: 'var(--text-3)' }} onClick={e => removeConv(c.id, e)} title="Delete">
                  <Icon d={I.trash} size={12} />
                </button>
              </div>
            ))}
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
              </div>
            ) : (
              <div key={i} className="self-start max-w-[80%] rounded-xl px-3.5 py-2.5 text-[12.5px] whitespace-pre-wrap"
                   style={{ background: 'var(--surface)', border: '1px solid var(--border)' }}>
                {m.content || (m.error && <span style={{ color: 'var(--red)' }}>⚠ {m.error}</span>)}
                {m.tool_calls?.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 mt-2">
                    {m.tool_calls.map((t, j) => (
                      <span key={j} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[9.5px] font-mono"
                            style={{ background: 'rgba(63,185,80,.12)', color: 'var(--green)' }}>
                        ⚙ {t}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
            {busy && (
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

          <div className="flex gap-2 p-3 border-t" style={{ borderColor: 'var(--border)' }}>
            {lastTokens && (
              <span className="self-center text-[9.5px] font-mono whitespace-nowrap mr-1" style={{ color: 'var(--text-3)' }}
                    title="token usage for the last chat turn">
                {lastTokens.total_tokens} tok
              </span>
            )}
            <textarea className="input flex-1 resize-none font-[13px]" rows={2} value={input}
                      onChange={e => setInput(e.target.value)}
                      onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() } }}
                      placeholder="e.g. Recon example.com — register the target and run the full pipeline…" />
            <button className="btn btn-primary flex items-center gap-1.5 self-stretch px-4" onClick={() => send()}
                    disabled={busy || !input.trim()}>
              <Icon d={I.send} /> Send
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
