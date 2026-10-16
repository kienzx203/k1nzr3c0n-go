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

  const load = useCallback(async () => {
    try { const r = await api.listTasks(); setTasks(r.items || []) } catch {}
  }, [])
  useEffect(() => { load(); api.listLLM().then(setProfiles).catch(() => {}); const t = setInterval(load, 4000); return () => clearInterval(t) }, [load])

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
              <button className="btn btn-primary" disabled={creating || !form.goal.trim()}>
                {creating ? 'Starting…' : '▶ Create & run'}
              </button>
              {!profiles.length && <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>No LLM profile yet — add one in AI Agent → LLM profile first.</p>}
            </form>
          </Card>

          <Card pad={false}>
            <div className="card-header px-3 py-2.5 text-[10px]">Tasks ({tasks.length})</div>
            <div className="overflow-y-auto" style={{ maxHeight: '48vh' }}>
              {tasks.map(t => (
                <div key={t.id} onClick={() => setSel(t.id)}
                     className="px-3 py-2.5 cursor-pointer border-b transition-colors"
                     style={{ borderColor: 'var(--border)', background: sel === t.id ? 'var(--surface-3)' : 'transparent' }}>
                  <div className="flex items-center gap-2">
                    <span className="text-[11.5px] font-medium truncate flex-1">{t.name || t.goal}</span>
                    <Badge tone={STATUS_TONE[t.status] || 'gray'}>{t.running ? 'running' : t.status}</Badge>
                  </div>
                  <div className="text-[9.5px] font-mono mt-1" style={{ color: 'var(--text-3)' }}>
                    #{t.id} · {t.counts?.intents || 0} intents · {t.counts?.facts || 0} facts · {t.counts?.findings || 0} findings · {timeAgo(t.created_at)}
                  </div>
                </div>
              ))}
              {!tasks.length && <div className="px-3 py-6 text-[11px] text-center" style={{ color: 'var(--text-3)' }}>No tasks yet — create one above.</div>}
            </div>
          </Card>
        </div>

        {/* right: detail */}
        <div className="min-w-0">
          {sel ? <TaskDetail id={sel} onDeleted={() => { setSel(null); load() }} /> :
            <Card><div className="py-16 text-center text-[12px]" style={{ color: 'var(--text-3)' }}>Select a task to view its exploration.</div></Card>}
        </div>
      </div>
    </div>
  )
}

function TaskDetail({ id, onDeleted }) {
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
        {tab === 'coverage' && (
          <div className="p-3">
            <div className="text-[10px] mb-2" style={{ color: 'var(--text-3)' }}>{coverage.tested} / {coverage.items.length} assets tested</div>
            <div className="flex flex-col gap-1">
              {coverage.items.map(a => (
                <div key={a.id} className="flex items-center gap-2 text-[11px] py-1 border-b" style={{ borderColor: 'var(--border)' }}>
                  <Badge tone={a.tested ? 'green' : 'gray'}>{a.tested ? 'tested' : 'untested'}</Badge>
                  <span className="font-mono text-[9.5px]" style={{ color: 'var(--text-3)' }}>{a.type}</span>
                  <span className="flex-1 truncate font-mono">{a.value}</span>
                </div>
              ))}
              {!coverage.items.length && <div className="py-10 text-center text-[11px]" style={{ color: 'var(--text-3)' }}>No in-scope assets yet.</div>}
            </div>
          </div>
        )}
      </div>
    </Card>
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
