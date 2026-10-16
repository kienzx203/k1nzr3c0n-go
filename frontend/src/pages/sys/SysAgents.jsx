import React, { useEffect, useState } from 'react'
import { api } from '../../api.js'
import { PageHeader, Card, Field, Badge } from '../../components/SysKit.jsx'

const IC = { d: <><circle cx="8" cy="8" r="6" /><circle cx="8" cy="8" r="2" /></>, color: 'var(--green)' }

export default function SysAgents() {
  const [prompt, setPrompt] = useState(null)
  const [roles, setRoles] = useState([])
  const [profiles, setProfiles] = useState([])

  const loadRoles = () => api.agentConfigs().then(r => setRoles(r.items || [])).catch(() => {})
  useEffect(() => {
    api.agentPrompt().then(p => setPrompt(p.system_prompt)).catch(() => {})
    api.listLLM().then(setProfiles).catch(() => {})
    loadRoles()
  }, [])

  return (
    <div className="fade-in p-6">
      <PageHeader icon={IC} title="Agents" sub="Exploration agent roles — configure prompt, LLM, run budget and tools per role" />

      {/* role management */}
      <div className="flex flex-col gap-3 mb-5">
        {roles.map(r => <RoleCard key={r.role} role={r} profiles={profiles} onSaved={loadRoles} />)}
        {!roles.length && <Card><div className="text-[11px]" style={{ color: 'var(--text-3)' }}>loading roles…</div></Card>}
      </div>

      {/* recon chat-agent persona (existing) */}
      <div className="section-title mb-2">Recon chat-agent persona</div>
      <Card>
        <pre className="whitespace-pre-wrap text-[11.5px] leading-relaxed" style={{ color: 'var(--text-2)' }}>
          {prompt || 'loading…'}
        </pre>
      </Card>
    </div>
  )
}

const ROLE_DESC = {
  goals: 'Decomposes the task goal and extracts scope.',
  planner: 'The only intent generator — reads the graph and queues directions.',
  worker: 'Executes one intent with real tools; writes facts/findings back.',
  mainagent: 'Human-in-the-loop operator channel (guidance / chat-in-task).',
  retester: 'Confirms whether a past vulnerability is still reproducible.',
}

function RoleCard({ role, profiles, onSaved }) {
  const [prompt, setPrompt] = useState(role.prompt || '')
  const [llm, setLlm] = useState(role.llm_profile_id || 0)
  const [steps, setSteps] = useState(role.max_steps || 0)
  const [enabled, setEnabled] = useState(role.enabled !== false)
  const [saving, setSaving] = useState(false)
  const [open, setOpen] = useState(false)

  async function save() {
    setSaving(true)
    try {
      await api.updateAgentConfig(role.role, { prompt, llm_profile_id: +llm || 0, max_steps: +steps || 0, enabled })
      onSaved && onSaved()
    } catch (e) { alert(e.message) } finally { setSaving(false) }
  }

  return (
    <Card pad={false}>
      <div className="card-header cursor-pointer" onClick={() => setOpen(o => !o)}>
        <div className="flex items-center gap-2">
          <Badge tone={enabled ? 'green' : 'gray'}>{role.role}</Badge>
          <span className="text-[12px] font-semibold">{role.name}</span>
          <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{ROLE_DESC[role.role]}</span>
        </div>
        <span className="text-[10px] font-mono" style={{ color: 'var(--text-3)' }}>
          {steps} steps · {llm ? (profiles.find(p => p.id === +llm)?.name || `#${llm}`) : 'auto LLM'} {open ? '▴' : '▾'}
        </span>
      </div>
      {open && (
        <div className="p-4 flex flex-col gap-3">
          <Field label="System prompt override (empty = built-in default)">
            <textarea className="input resize-none font-mono text-[11px]" rows={5} value={prompt}
                      placeholder="Leave empty to use the built-in prompt for this role…"
                      onChange={e => setPrompt(e.target.value)} />
          </Field>
          <div className="grid grid-cols-3 gap-3">
            <Field label="Bound LLM">
              <select className="input" value={llm} onChange={e => setLlm(e.target.value)}>
                <option value={0}>auto (task/global)</option>
                {profiles.map(p => <option key={p.id} value={p.id}>{p.name} · {p.model}</option>)}
              </select>
            </Field>
            <Field label="Run budget (max steps)">
              <input className="input" type="number" min={0} value={steps} onChange={e => setSteps(e.target.value)} />
            </Field>
            <Field label="Enabled">
              <select className="input" value={enabled ? '1' : '0'} onChange={e => setEnabled(e.target.value === '1')}>
                <option value="1">enabled</option>
                <option value="0">disabled</option>
              </select>
            </Field>
          </div>
          <div className="flex justify-end">
            <button className="btn btn-primary text-[11px]" disabled={saving} onClick={save}>{saving ? 'Saving…' : 'Save role'}</button>
          </div>
        </div>
      )}
    </Card>
  )
}
