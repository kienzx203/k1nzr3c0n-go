import React, { useEffect, useRef, useState, useCallback } from 'react'
import { api, wsTaskUrl } from '../../api.js'
import { PageHeader, Card, Field, Badge } from '../../components/SysKit.jsx'
import { timeAgo } from '../../utils.js'

const IC = { d: <path d="M3 3h6v6H3zM7 13h6v-2l3 3-3 3v-2H7z" />, color: 'var(--green)' }

const STATUS_TONE = { running: 'green', done: 'blue', created: 'gray', paused: 'amber', failed: 'red', timeout: 'red' }
const NODE_TONE = { goal: 'blue', intent: 'amber', fact: 'green', finding: 'red', hint: 'gray', digest: 'gray', begin: 'gray' }

export default function Tasks() {
  const [tasks, setTasks] = useState([])
  const [sel, setSel] = useState(null)
  const [profiles, setProfiles] = useState([])
  const [form, setForm] = useState({ name: '', goal: '', max_workers: 3, timeout_seconds: 0, llm_profile_id: 0 })
  const [creating, setCreating] = useState(false)
  const [err, setErr] = useState('')
  const [templates, setTemplates] = useState([])
  const [categories, setCategories] = useState([])
  const [showArchived, setShowArchived] = useState(false)
  const [catFilter, setCatFilter] = useState(0)

  const load = useCallback(async () => {
    try { const r = await (showArchived ? api.listTasksArchived() : api.listTasks()); setTasks(r.items || []) } catch {}
  }, [showArchived])
  const loadMeta = useCallback(() => {
    api.listTemplates().then(r => setTemplates(r.items || [])).catch(() => {})
    api.listCategories().then(r => setCategories(r.items || [])).catch(() => {})
  }, [])
  useEffect(() => { load(); api.listLLM().then(setProfiles).catch(() => {}); loadMeta(); const t = setInterval(load, 4000); return () => clearInterval(t) }, [load, loadMeta])

  async function saveAsTemplate() {
    if (!form.goal.trim()) { setErr('Enter a goal to save as a template'); return }
    const name = prompt('Template name:', form.name || form.goal.slice(0, 30))
    if (!name) return
    try { await api.createTemplate({ name, goal: form.goal, description: '', max_workers: +form.max_workers }); loadMeta() } catch (e) { setErr(e.message) }
  }
  async function launchTpl(id) { try { const t = await api.launchTemplate(id, true); await load(); setSel(t.id) } catch (e) { setErr(e.message) } }
  async function assignCat(taskId, catId) { try { await api.setTaskCategory(taskId, catId); load() } catch {} }
  async function newCategory() {
    const name = prompt('Category name:'); if (!name) return
    try { await api.createCategory(name, '#5b9bff'); loadMeta() } catch (e) { setErr(e.message) }
  }
  const shownTasks = catFilter ? tasks.filter(t => t.category_id === catFilter) : tasks

  async function create(e) {
    e.preventDefault()
    if (!form.goal.trim()) return
    setCreating(true); setErr('')
    try {
      const body = { ...form, max_workers: +form.max_workers, timeout_seconds: +form.timeout_seconds,
        llm_profile_id: +form.llm_profile_id || 0, autostart: true }
      const t = await api.createTask(body)
      setForm({ name: '', goal: '', max_workers: 3, timeout_seconds: 0, llm_profile_id: 0 })
      await load()
      setSel(t.id)
      if (t.start_error) setErr('Created, but could not start: ' + t.start_error)
    } catch (e2) { setErr(e2.message) } finally { setCreating(false) }
  }

  return (
    <div className="fade-in p-6">
      <PageHeader icon={IC} title="Tasks" sub="Autonomous goal-driven exploration — planner → workers → findings (two-graph engine)" />
      <div className="grid gap-4" style={{ gridTemplateColumns: '320px 1fr' }}>
        {/* left: create + list */}
        <div className="flex flex-col gap-3 min-w-0">
          <Card>
            <form onSubmit={create} className="flex flex-col gap-2.5">
              <Field label="Goal">
                <textarea className="input resize-none" rows={2} placeholder="e.g. Full recon of example.com and find auth bypasses"
                          value={form.goal} onChange={e => setForm({ ...form, goal: e.target.value })} />
              </Field>
              <div className="grid grid-cols-2 gap-2">
                <Field label="Name"><input className="input" value={form.name} placeholder="optional" onChange={e => setForm({ ...form, name: e.target.value })} /></Field>
                <Field label="Workers"><input className="input" type="number" min={1} max={8} value={form.max_workers} onChange={e => setForm({ ...form, max_workers: e.target.value })} /></Field>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <Field label="LLM profile">
                  <select className="input" value={form.llm_profile_id} onChange={e => setForm({ ...form, llm_profile_id: e.target.value })}>
                    <option value={0}>auto (first)</option>
                    {profiles.map(p => <option key={p.id} value={p.id}>{p.name} · {p.model}</option>)}
                  </select>
                </Field>
                <Field label="Timeout (s)"><input className="input" type="number" min={0} value={form.timeout_seconds} onChange={e => setForm({ ...form, timeout_seconds: e.target.value })} /></Field>
              </div>
              {err && <p className="text-[10.5px]" style={{ color: 'var(--red)' }}>⚠ {err}</p>}
              <div className="flex gap-2">
                <button className="btn btn-primary flex-1" disabled={creating || !form.goal.trim()}>
                  {creating ? 'Starting…' : '▶ Create & run'}
                </button>
                <button type="button" className="btn text-[11px]" onClick={saveAsTemplate} title="Save as template">💾 Template</button>
              </div>
              {!profiles.length && <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>No LLM profile yet — add one in AI Agent → LLM profile first.</p>}
            </form>
          </Card>

          {/* templates */}
          {templates.length > 0 && (
            <Card pad={false}>
              <div className="card-header px-3 py-2.5 text-[10px]">Templates</div>
              <div className="overflow-y-auto" style={{ maxHeight: '18vh' }}>
                {templates.map(t => (
                  <div key={t.id} className="group flex items-center gap-2 px-3 py-1.5 border-b" style={{ borderColor: 'var(--border)' }}>
                    <span className="text-[11px] truncate flex-1">{t.name}</span>
                    <button className="btn btn-accent text-[9.5px] px-2 py-0.5" onClick={() => launchTpl(t.id)}>Launch</button>
                    <button className="opacity-0 group-hover:opacity-100 text-[10px]" style={{ color: 'var(--text-3)' }} onClick={() => api.deleteTemplate(t.id).then(loadMeta)}>✕</button>
                  </div>
                ))}
              </div>
            </Card>
          )}

          <Card pad={false}>
            <div className="card-header px-3 py-2.5 text-[10px] flex-wrap gap-1">
              Tasks ({shownTasks.length})
              <div className="ml-auto flex items-center gap-1.5">
                <button className="text-[9.5px] hover:underline" style={{ color: showArchived ? 'var(--accent)' : 'var(--text-3)' }}
                        onClick={() => setShowArchived(v => !v)}>{showArchived ? 'archived' : 'active'}</button>
                <button className="text-[9.5px] hover:underline" style={{ color: 'var(--text-3)' }} onClick={newCategory}>+cat</button>
              </div>
            </div>
            {/* category filter chips */}
            {categories.length > 0 && (
              <div className="flex flex-wrap gap-1 px-3 py-1.5 border-b" style={{ borderColor: 'var(--border)' }}>
                <button className="text-[9px] px-1.5 py-0.5 rounded-full border" onClick={() => setCatFilter(0)}
                        style={{ borderColor: catFilter === 0 ? 'var(--accent)' : 'var(--border)', color: catFilter === 0 ? 'var(--accent)' : 'var(--text-3)' }}>all</button>
                {categories.map(c => (
                  <button key={c.id} className="text-[9px] px-1.5 py-0.5 rounded-full border" onClick={() => setCatFilter(c.id)}
                          style={{ borderColor: catFilter === c.id ? c.color : 'var(--border)', color: catFilter === c.id ? c.color : 'var(--text-3)' }}>{c.name}</button>
                ))}
              </div>
            )}
            <div className="overflow-y-auto" style={{ maxHeight: '42vh' }}>
              {shownTasks.map(t => (
                <div key={t.id} onClick={() => setSel(t.id)}
                     className="px-3 py-2.5 cursor-pointer border-b transition-colors"
                     style={{ borderColor: 'var(--border)', background: sel === t.id ? 'var(--surface-3)' : 'transparent' }}>
                  <div className="flex items-center gap-2">
                    {t.category_id > 0 && <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: categories.find(c => c.id === t.category_id)?.color || 'var(--text-3)' }} />}
                    <span className="text-[11.5px] font-medium truncate flex-1">{t.name || t.goal}</span>
                    <Badge tone={STATUS_TONE[t.status] || 'gray'}>{t.running ? 'running' : t.status}</Badge>
                  </div>
                  <div className="text-[9.5px] font-mono mt-1" style={{ color: 'var(--text-3)' }}>
                    #{t.id} · {t.counts?.intents || 0} intents · {t.counts?.facts || 0} facts · {t.counts?.findings || 0} findings · {timeAgo(t.created_at)}
                  </div>
                </div>
              ))}
              {!shownTasks.length && <div className="px-3 py-6 text-[11px] text-center" style={{ color: 'var(--text-3)' }}>{showArchived ? 'No archived tasks.' : 'No tasks yet — create one above.'}</div>}
            </div>
          </Card>
        </div>

        {/* right: detail */}
        <div className="min-w-0">
          {sel ? <TaskDetail id={sel} categories={categories} onCategory={assignCat} onDeleted={() => { setSel(null); load() }} onArchived={() => { setSel(null); load() }} /> :
            <Card><div className="py-16 text-center text-[12px]" style={{ color: 'var(--text-3)' }}>Select a task to view its exploration.</div></Card>}
        </div>
      </div>
    </div>
  )
}

function TaskDetail({ id, onDeleted, onArchived, categories = [], onCategory }) {
  const [task, setTask] = useState(null)
  const [tab, setTab] = useState('activity')
  const [activity, setActivity] = useState([])
  const [graph, setGraph] = useState({ nodes: [], edges: [] })
  const [coverage, setCoverage] = useState({ items: [], tested: 0 })
  const [questions, setQuestions] = useState([])
  const [guidance, setGuidance] = useState('')
  const wsRef = useRef(null)
  const feedRef = useRef(null)

  const reload = useCallback(async () => {
    try { setTask(await api.getTask(id)) } catch {}
    try { setQuestions((await api.taskQuestions(id)).items || []) } catch {}
  }, [id])

  async function answer(qid, text) {
    try { await api.answerQuestion(qid, text); reload() } catch (e) { alert(e.message) }
  }
  async function sendGuidance() {
    if (!guidance.trim()) return
    try { await api.taskMessage(id, guidance); setGuidance('') } catch (e) { alert(e.message) }
  }

  useEffect(() => {
    reload()
    const t = setInterval(reload, 3000)
    return () => clearInterval(t)
  }, [reload])

  useEffect(() => {
    if (tab === 'graph') api.taskGraph(id).then(setGraph).catch(() => {})
    if (tab === 'coverage') api.taskCoverage(id).then(setCoverage).catch(() => {})
    if (tab === 'activity') api.taskActivity(id).then(r => setActivity((r.items || []).slice().reverse())).catch(() => {})
  }, [tab, id, task?.counts?.facts, task?.counts?.findings])

  // live event stream
  useEffect(() => {
    const ws = new WebSocket(wsTaskUrl(id))
    wsRef.current = ws
    ws.onmessage = ev => {
      try {
        const m = JSON.parse(ev.data)
        if (m.type === 'log' && m.message) {
          const e = JSON.parse(m.message)
          setActivity(a => [...a.slice(-400), { live: true, ...e }])
          setTimeout(() => feedRef.current?.scrollTo(0, feedRef.current.scrollHeight), 30)
        }
      } catch {}
    }
    return () => ws.close()
  }, [id])

  if (!task) return <Card><div className="py-16 text-center text-[12px]" style={{ color: 'var(--text-3)' }}>Loading…</div></Card>
  const c = task.counts || {}
  const busy = task.running

  const ctl = async fn => { try { await fn(); reload() } catch (e) { alert(e.message) } }

  return (
    <Card pad={false}>
      {/* header */}
      <div className="card-header flex-wrap gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-[13px] font-bold truncate">{task.name || task.goal}</span>
            <Badge tone={STATUS_TONE[task.status] || 'gray'}>{busy ? 'running' : task.status}</Badge>
          </div>
          <div className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>#{task.id} · {task.goal}</div>
        </div>
        <div className="ml-auto flex gap-1.5">
          {!busy && task.status !== 'done' && <button className="btn btn-primary text-[11px]" onClick={() => ctl(() => api.startTask(id))}>▶ Start</button>}
          {busy && <button className="btn btn-warning text-[11px]" onClick={() => ctl(() => api.pauseTask(id))}>⏸ Pause</button>}
          {busy && <button className="btn btn-danger text-[11px]" onClick={() => ctl(() => api.stopTask(id))}>■ Stop</button>}
          {categories.length > 0 && (
            <select className="input text-[10px] py-1 w-28" value={task.category_id || 0} onChange={e => onCategory && onCategory(id, +e.target.value)}>
              <option value={0}>no category</option>
              {categories.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          )}
          {task.archived_at ? (
            <button className="btn text-[11px]" onClick={() => api.restoreTask(id).then(() => reload())}>Restore</button>
          ) : (
            <button className="btn text-[11px]" onClick={() => { if (confirm('Archive task?')) api.archiveTask(id).then(onArchived) }}>Archive</button>
          )}
          <button className="btn btn-ghost text-[11px]" onClick={() => { if (confirm('Delete task?')) api.deleteTask(id).then(onDeleted) }}>Delete</button>
        </div>
      </div>

      {/* stat row */}
      <div className="grid grid-cols-4 gap-px" style={{ background: 'var(--border)' }}>
        {[['Intents', c.intents, c.open_intents + ' open'], ['Facts', c.facts], ['Findings', c.findings], ['Hints', c.hints]].map(([l, v, sub]) => (
          <div key={l} className="p-3" style={{ background: 'var(--surface)' }}>
            <div className="text-[9px] uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>{l}</div>
            <div className="text-[20px] font-bold font-mono leading-none mt-1">{v ?? 0}</div>
            {sub != null && <div className="text-[9px] mt-1" style={{ color: 'var(--text-3)' }}>{sub}</div>}
          </div>
        ))}
      </div>

      {/* pending human-in-the-loop questions */}
      {questions.filter(q => q.status === 'pending').map(q => (
        <QuestionRow key={q.id} q={q} onAnswer={answer} onSkip={() => api.skipQuestion(q.id).then(reload)} />
      ))}

      {/* operator guidance (mainagent chat-in-task) */}
      <div className="px-4 py-2.5 border-b flex gap-2" style={{ borderColor: 'var(--border)' }}>
        <input className="input text-[11px]" placeholder="Send guidance to the planner (mainagent chat)…"
               value={guidance} onChange={e => setGuidance(e.target.value)}
               onKeyDown={e => { if (e.key === 'Enter') sendGuidance() }} />
        <button className="btn btn-accent text-[11px]" onClick={sendGuidance} disabled={!guidance.trim()}>Send</button>
      </div>

      {/* todolist */}
      {task.todolist && (
        <div className="px-4 py-2.5 border-b text-[10.5px] whitespace-pre-wrap font-mono" style={{ borderColor: 'var(--border)', color: 'var(--text-2)', maxHeight: 120, overflow: 'auto' }}>
          <span className="text-[9px] uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Planner todolist</span>
          {'\n'}{task.todolist}
        </div>
      )}

      {/* tabs */}
      <div className="flex border-b" style={{ borderColor: 'var(--border)' }}>
        {['activity', 'graph', 'coverage'].map(tb => (
          <button key={tb} onClick={() => setTab(tb)} className="px-4 py-2 text-[10.5px] font-semibold uppercase tracking-wider"
                  style={{ borderBottom: `2px solid ${tab === tb ? 'var(--accent)' : 'transparent'}`, color: tab === tb ? 'var(--accent)' : 'var(--text-2)' }}>
            {tb}
          </button>
        ))}
      </div>

      {/* tab body */}
      <div ref={feedRef} className="overflow-y-auto" style={{ maxHeight: '46vh' }}>
        {tab === 'activity' && (
          <div className="p-3 flex flex-col gap-1.5">
            {activity.map((a, i) => <ActivityRow key={i} a={a} />)}
            {!activity.length && <div className="py-10 text-center text-[11px]" style={{ color: 'var(--text-3)' }}>No activity yet.</div>}
          </div>
        )}
        {tab === 'graph' && (
          <div className="p-3 flex flex-col gap-1">
            {graph.nodes.map(n => (
              <div key={n.id} className="flex items-start gap-2 text-[11px] py-1 border-b" style={{ borderColor: 'var(--border)' }}>
                <Badge tone={NODE_TONE[n.kind] || 'gray'}>{n.kind}</Badge>
                <span className="font-mono text-[9.5px]" style={{ color: 'var(--text-3)' }}>#{n.id}</span>
                <span className="flex-1 truncate" style={{ color: 'var(--text-2)' }}>
                  {n.payload?.description || n.payload?.summary || n.payload?.title || n.payload?.goal || n.state}
                </span>
                <span className="text-[9px]" style={{ color: 'var(--text-3)' }}>{n.state}</span>
              </div>
            ))}
            {!graph.nodes.length && <div className="py-10 text-center text-[11px]" style={{ color: 'var(--text-3)' }}>Graph is empty.</div>}
          </div>
        )}
        {tab === 'coverage' && <CoverageGraph coverage={coverage} />}
      </div>
    </Card>
  )
}

// CoverageGraph visualizes in-scope assets grouped by type, each cell colored by
// whether this task has probed it (the ScopeWeaver asset-coverage graph).
function CoverageGraph({ coverage }) {
  const items = coverage.items || []
  const total = items.length
  const tested = coverage.tested || 0
  const pct = total ? Math.round((tested / total) * 100) : 0
  const byType = {}
  for (const a of items) (byType[a.type] = byType[a.type] || []).push(a)
  const R = 26, C = 2 * Math.PI * R
  return (
    <div className="p-4">
      {/* progress ring */}
      <div className="flex items-center gap-4 mb-4">
        <svg width="64" height="64" viewBox="0 0 64 64">
          <circle cx="32" cy="32" r={R} fill="none" stroke="var(--surface-3)" strokeWidth="7" />
          <circle cx="32" cy="32" r={R} fill="none" stroke="var(--green)" strokeWidth="7" strokeLinecap="round"
                  strokeDasharray={`${C * pct / 100} ${C}`} transform="rotate(-90 32 32)" />
          <text x="32" y="36" textAnchor="middle" fontSize="14" fontWeight="700" fill="var(--text)">{pct}%</text>
        </svg>
        <div>
          <div className="text-[13px] font-bold">{tested} / {total} assets tested</div>
          <div className="text-[10px]" style={{ color: 'var(--text-3)' }}>In-scope assets probed by this task's intents</div>
        </div>
      </div>
      {/* grid by type */}
      {total === 0 && <div className="py-10 text-center text-[11px]" style={{ color: 'var(--text-3)' }}>No in-scope assets yet.</div>}
      {Object.entries(byType).map(([type, list]) => (
        <div key={type} className="mb-3">
          <div className="text-[9.5px] uppercase tracking-wider font-semibold mb-1.5" style={{ color: 'var(--text-3)' }}>
            {type} <span style={{ color: 'var(--green)' }}>({list.filter(a => a.tested).length}</span>/{list.length})
          </div>
          <div className="flex flex-wrap gap-1">
            {list.map(a => (
              <span key={a.id} title={`${a.value} — ${a.tested ? 'tested' : 'untested'}`}
                    className="text-[9px] font-mono px-1.5 py-1 rounded truncate max-w-[180px]"
                    style={{
                      background: a.tested ? 'rgba(53,208,127,.16)' : 'var(--surface-2)',
                      color: a.tested ? 'var(--green)' : 'var(--text-3)',
                      border: `1px solid ${a.tested ? 'rgba(53,208,127,.4)' : 'var(--border)'}`,
                    }}>
                {a.tested ? '●' : '○'} {a.value}
              </span>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}

function QuestionRow({ q, onAnswer, onSkip }) {
  const [text, setText] = useState('')
  return (
    <div className="px-4 py-3 border-b" style={{ borderColor: 'var(--amber)', background: 'rgba(242,201,76,.06)' }}>
      <div className="flex items-center gap-2 mb-2">
        <span className="badge text-[9px] font-mono" style={{ background: 'rgba(242,201,76,.16)', color: 'var(--amber)' }}>❓ worker asks</span>
        <span className="text-[9.5px] font-mono" style={{ color: 'var(--text-3)' }}>{q.worker}</span>
      </div>
      <div className="text-[12px] mb-2" style={{ color: 'var(--text)' }}>{q.question}</div>
      <div className="flex gap-2">
        <input className="input text-[11px]" placeholder="Your answer…" value={text}
               onChange={e => setText(e.target.value)}
               onKeyDown={e => { if (e.key === 'Enter' && text.trim()) onAnswer(q.id, text) }} />
        <button className="btn btn-primary text-[11px]" disabled={!text.trim()} onClick={() => onAnswer(q.id, text)}>Answer</button>
        <button className="btn btn-ghost text-[11px]" onClick={onSkip}>Skip</button>
      </div>
    </div>
  )
}

function ActivityRow({ a }) {
  const ev = a.event || a.kind
  const color = a.is_error ? 'var(--red)' : ev === 'finding' ? 'var(--red)' : ev === 'fact' ? 'var(--green)' : ev === 'intent' ? 'var(--amber)' : 'var(--text-2)'
  const icon = { intent: '◆', claim: '▸', fact: '✓', finding: '⚑', step: '$', status: '●', 'intent-done': '□' }[ev] || '·'
  const text = a.description || a.summary || a.title || a.command || a.reason || a.status || a.detail || ''
  return (
    <div className="flex items-start gap-2 text-[11px] font-mono leading-snug">
      <span style={{ color }}>{icon}</span>
      <span className="flex-1 whitespace-pre-wrap break-words" style={{ color }}>
        {ev && <span style={{ color: 'var(--text-3)' }}>[{ev}] </span>}{String(text).slice(0, 500)}
      </span>
    </div>
  )
}
