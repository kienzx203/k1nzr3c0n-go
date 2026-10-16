import React, { useEffect, useState, useRef } from 'react'
import { api } from '../../api.js'
import { PageHeader, Card, Field } from '../../components/SysKit.jsx'

const IC = { d: <path d="M8 1.5 13.5 4v4c0 3.5-2.5 5.5-5.5 6.5C5 13.5 2.5 11.5 2.5 8V4z" />, color: 'var(--green)' }

export default function SysSkills() {
  const [skills, setSkills] = useState([])
  const [overview, setOverview] = useState(null)
  const [sel, setSel] = useState(null)
  const [creating, setCreating] = useState(false)
  const fileRef = useRef(null)

  const load = () => {
    api.skillsList().then(r => setSkills(r || [])).catch(() => {})
    api.skillOverview().then(setOverview).catch(() => {})
  }
  useEffect(() => { load() }, [])

  async function upload(e) {
    const f = e.target.files?.[0]; if (!f) return
    try { await api.uploadSkill(f); load() } catch (err) { alert(err.message) } finally { if (fileRef.current) fileRef.current.value = '' }
  }
  async function del(name) {
    if (!confirm(`Delete skill "${name}"?`)) return
    try { await api.deleteSkill(name); if (sel === name) setSel(null); load() } catch (e) { alert(e.message) }
  }

  return (
    <div className="fade-in p-6">
      <PageHeader icon={IC} title="Skill" sub="Skill library · agentskills.io specification · Per-Agent visibility" />
      <div className="grid gap-4" style={{ gridTemplateColumns: '300px 1fr' }}>
        {/* left: actions + tree */}
        <div className="flex flex-col gap-2.5 min-w-0">
          <button className="btn btn-primary" onClick={() => setCreating(true)}>+ New skill</button>
          <button className="btn" onClick={() => fileRef.current?.click()}>⬆ Upload archive</button>
          <input ref={fileRef} type="file" accept=".zip,.tar.gz,.tgz" className="hidden" onChange={upload} />
          <Card pad={false}>
            <div className="overflow-y-auto" style={{ maxHeight: '64vh' }}>
              {skills.map(sk => <SkillTreeItem key={sk.name} sk={sk} active={sel === sk.name} onSelect={() => setSel(sk.name)} onDelete={() => del(sk.name)} />)}
              {!skills.length && <div className="px-3 py-6 text-[11px] text-center" style={{ color: 'var(--text-3)' }}>No skills under &lt;base&gt;/skills/</div>}
            </div>
          </Card>
        </div>

        {/* right: overview or skill detail */}
        <div className="min-w-0">
          {creating ? <NewSkill onClose={() => setCreating(false)} onSaved={() => { setCreating(false); load() }} />
            : sel ? <SkillDetail name={sel} />
            : <Overview overview={overview} onPick={setSel} />}
        </div>
      </div>
    </div>
  )
}

function SkillTreeItem({ sk, active, onSelect, onDelete }) {
  const [open, setOpen] = useState(false)
  const [files, setFiles] = useState(null)
  const toggle = async (e) => {
    e.stopPropagation(); setOpen(o => !o)
    if (!files) { try { setFiles((await api.skillFiles(sk.name)).files || []) } catch { setFiles([]) } }
  }
  return (
    <div className="border-b" style={{ borderColor: 'var(--border)' }}>
      <div className="group flex items-center gap-1.5 px-3 py-2 cursor-pointer" onClick={onSelect}
           style={{ background: active ? 'var(--surface-3)' : 'transparent' }}>
        <button onClick={toggle} className="text-[10px] w-3" style={{ color: 'var(--text-3)' }}>{open ? '▾' : '▸'}</button>
        <span style={{ color: 'var(--amber)' }}>📁</span>
        <span className="text-[12px] font-semibold truncate flex-1">{sk.name}</span>
        <button className="opacity-0 group-hover:opacity-100 text-[10px]" style={{ color: 'var(--text-3)' }} onClick={e => { e.stopPropagation(); onDelete() }}>✕</button>
      </div>
      {open && files && (
        <div className="pl-7 pb-1.5">
          {files.map(f => <div key={f.path} className="text-[10.5px] font-mono py-0.5" style={{ color: 'var(--text-3)' }}>📄 {f.path}</div>)}
          {!files.length && <div className="text-[10px]" style={{ color: 'var(--text-3)' }}>(empty)</div>}
        </div>
      )}
    </div>
  )
}

function Stat({ value, label, sub, color }) {
  return (
    <div className="card p-4">
      <div className="text-[28px] leading-none font-bold font-mono" style={{ color: color || 'var(--text)' }}>{value}</div>
      <div className="text-[11px] font-semibold mt-2">{label}</div>
      {sub != null && <div className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{sub}</div>}
    </div>
  )
}

function Overview({ overview, onPick }) {
  const o = overview || {}
  const ranking = o.call_ranking || []
  const recent = o.recent_calls || []
  const unused = o.unused_skills || []
  return (
    <div className="fade-in">
      <h2 className="text-[16px] font-bold mb-1">Skill library overview</h2>
      <p className="text-[12px] mb-4" style={{ color: 'var(--text-3)' }}>Select a skill on the left for details and call history, or review overall usage here.</p>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
        <Stat value={o.total_skills ?? 0} label="Total skills" sub={`${o.called_skills ?? 0} have been called`} />
        <Stat value={o.total_calls ?? 0} label="Total calls" />
        <Stat value={o.unused_count ?? 0} label="Unused" sub="Never loaded by any Agent" color={o.unused_count ? 'var(--amber)' : undefined} />
        <Stat value={o.unmatched_calls ?? 0} label="Unmatched calls" sub={o.unmatched_calls ? '' : 'None'} color={o.unmatched_calls ? 'var(--red)' : undefined} />
      </div>

      <div className="section-title mb-2">Call ranking</div>
      <Card>
        {ranking.length === 0 ? (
          <div className="py-6 text-center text-[12px]" style={{ color: 'var(--text-3)' }}>No skill call records yet.</div>
        ) : (
          <div className="flex flex-col gap-1.5">
            {ranking.map((r, i) => (
              <div key={r.skill} className="flex items-center gap-2 text-[12px]">
                <span className="font-mono w-5" style={{ color: 'var(--text-3)' }}>#{i + 1}</span>
                <span className="font-semibold cursor-pointer hover:underline" style={{ color: 'var(--accent)' }} onClick={() => onPick(r.skill)}>{r.skill}</span>
                <span className="ml-auto font-mono" style={{ color: 'var(--text-2)' }}>{r.calls} calls</span>
              </div>
            ))}
          </div>
        )}
      </Card>

      <div className="grid md:grid-cols-2 gap-4 mt-5">
        <div>
          <div className="section-title mb-2">Recent calls</div>
          {recent.length === 0 ? <p className="text-[12px]" style={{ color: 'var(--text-3)' }}>No records yet.</p>
            : <Card pad={false}><div className="overflow-y-auto" style={{ maxHeight: 220 }}>
                {recent.map(c => (
                  <div key={c.id} className="flex items-center gap-2 px-3 py-1.5 border-b text-[11px]" style={{ borderColor: 'var(--border)' }}>
                    <span style={{ color: c.found ? 'var(--green)' : 'var(--red)' }}>{c.found ? '✓' : '✕'}</span>
                    <span className="font-semibold">{c.skill}</span>
                    <span className="font-mono text-[10px]" style={{ color: 'var(--text-3)' }}>{c.agent_key}</span>
                    <span className="ml-auto text-[10px]" style={{ color: 'var(--text-3)' }}>{(c.created_at || '').replace('T', ' ').slice(0, 19)}</span>
                  </div>
                ))}
              </div></Card>}
        </div>
        <div>
          <div className="section-title mb-2">Unused skills <span style={{ color: 'var(--text-3)' }}>({unused.length})</span></div>
          <div className="flex flex-wrap gap-1.5">
            {unused.map(n => (
              <span key={n} className="text-[11px] px-2 py-1 rounded-full border cursor-pointer" onClick={() => onPick(n)}
                    style={{ borderColor: 'var(--border)', color: 'var(--text-2)', background: 'var(--surface-2)' }}>{n}</span>
            ))}
            {!unused.length && <span className="text-[12px]" style={{ color: 'var(--text-3)' }}>None</span>}
          </div>
        </div>
      </div>
    </div>
  )
}

function SkillDetail({ name }) {
  const [files, setFiles] = useState([])
  const [content, setContent] = useState('')
  const [active, setActive] = useState('')
  const [usage, setUsage] = useState([])
  useEffect(() => {
    setContent(''); setActive('')
    api.skillFiles(name).then(r => {
      const fs = r.files || []; setFiles(fs)
      const main = fs.find(f => f.path === 'SKILL.md') || fs[0]
      if (main) openFile(main.path)
    }).catch(() => {})
    api.skillUsage(name).then(r => setUsage(r.calls || [])).catch(() => {})
  }, [name])
  async function openFile(p) { setActive(p); try { setContent((await api.skillFileGet(name, p)).content || '') } catch { setContent('(cannot read)') } }
  return (
    <div className="fade-in">
      <h2 className="text-[16px] font-bold mb-1">{name}</h2>
      <p className="text-[11px] mb-3" style={{ color: 'var(--text-3)' }}>{usage.length} call{usage.length === 1 ? '' : 's'} recorded</p>
      <div className="flex gap-1.5 mb-2 flex-wrap">
        {files.map(f => (
          <button key={f.path} className="btn text-[10.5px] px-2 py-1" onClick={() => openFile(f.path)}
                  style={active === f.path ? { background: 'var(--surface-3)', color: 'var(--accent)' } : {}}>{f.path}</button>
        ))}
      </div>
      <Card pad={false}>
        <pre className="m-0 p-3 whitespace-pre-wrap text-[11px] leading-relaxed font-mono overflow-auto" style={{ color: 'var(--text-2)', maxHeight: '60vh' }}>{content || 'loading…'}</pre>
      </Card>
    </div>
  )
}

function NewSkill({ onClose, onSaved }) {
  const [form, setForm] = useState({ name: '', description: '', content: '' })
  const [saving, setSaving] = useState(false)
  const [err, setErr] = useState('')
  async function save() {
    if (!form.name.trim()) { setErr('Name is required'); return }
    setSaving(true); setErr('')
    try { await api.createSkill(form); onSaved() } catch (e) { setErr(e.message) } finally { setSaving(false) }
  }
  return (
    <Card>
      <div className="flex items-center mb-3">
        <h2 className="text-[15px] font-bold">New skill</h2>
        <button className="btn btn-ghost text-[11px] ml-auto" onClick={onClose}>✕ Close</button>
      </div>
      <div className="flex flex-col gap-3" style={{ maxWidth: 560 }}>
        <Field label="Name (folder)"><input className="input" value={form.name} placeholder="e.g. my-recon-skill" onChange={e => setForm({ ...form, name: e.target.value })} /></Field>
        <Field label="Description"><input className="input" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} /></Field>
        <Field label="SKILL.md body (markdown)"><textarea className="input resize-none font-mono text-[11px]" rows={10} value={form.content} placeholder="Instructions the agent follows when it loads this skill…" onChange={e => setForm({ ...form, content: e.target.value })} /></Field>
        {err && <p className="text-[10.5px]" style={{ color: 'var(--red)' }}>⚠ {err}</p>}
        <button className="btn btn-primary" disabled={saving} onClick={save}>{saving ? 'Saving…' : 'Create skill'}</button>
        <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>Frontmatter (name/description) is added automatically if you don't include a <code>---</code> block.</p>
      </div>
    </Card>
  )
}
