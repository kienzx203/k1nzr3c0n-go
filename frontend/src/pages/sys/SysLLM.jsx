import React from 'react'
import { useEffect, useState } from 'react'
import { api } from '../../api.js'
import { PageHeader, Card, Table, Field, Badge } from '../../components/SysKit.jsx'

const IC = { d: <path d="M8 1.5 9.5 6.5 14.5 8 9.5 9.5 8 14.5 6.5 9.5 1.5 8 6.5 6.5z" />, color: 'var(--accent)' }
export default function SysLLM() {
  const [profiles, setProfiles] = useState(null)
  const [form, setForm] = useState({ name: '', base_url: 'https://api.z.ai/api/coding/paas/v4', api_key: '', model: 'glm-4.7' })
  const [err, setErr] = useState('')
  const load = () => api.listLLM().then(setProfiles).catch(() => {})
  useEffect(() => { load() }, [])
  async function create(e) { e.preventDefault(); setErr('')
    try { await api.createLLM(form); setForm({ ...form, api_key: '' }); load() } catch (e2) { setErr(e2.message) } }
  return (
    <div className="fade-in">
      <PageHeader icon={IC} title="LLM Profiles" sub="Failover chain — the agent falls back to the next profile on 401/429/quota/5xx" />
      <div className="grid gap-4 mb-4" style={{ gridTemplateColumns: '1fr 340px' }}>
        <Table head={['#', 'Name', 'Model', 'Base URL', 'Key']}
          rows={(profiles || []).map(p => [p.id, p.name, <Badge tone="blue">{p.model}</Badge>,
            <span className="font-mono text-[10px]">{p.base_url}</span>,
            <span className="font-mono text-[10px]" style={{ color: 'var(--text-3)' }}>{p.api_key_masked}</span>])}
          empty="No profiles" />
        <Card>
          <form onSubmit={create} className="flex flex-col gap-2.5">
            <Field label="Name"><input className="input" value={form.name} required onChange={e => setForm({ ...form, name: e.target.value })} /></Field>
            <Field label="Preset">
              <select className="input text-[11px]" value={form.base_url} onChange={e => setForm({ ...form, base_url: e.target.value, model: e.target.selectedOptions[0].dataset.model || form.model })}>
                <option value="https://api.z.ai/api/coding/paas/v4" data-model="glm-4.7">Z.ai Coding Plan — glm-4.7</option>
                <option value="https://api.z.ai/api/paas/v4" data-model="glm-4.7">Z.ai General API — glm-4.7</option>
                <option value="https://api.z.ai/api/paas/v4" data-model="glm-4.5-flash">Z.ai Free — glm-4.5-flash</option>
                <option value="http://127.0.0.1:11434/v1" data-model="llama3.1">Ollama local</option>
                <option value="">Custom…</option>
              </select>
            </Field>
            <Field label="Base URL"><input className="input font-mono text-[10.5px]" value={form.base_url} onChange={e => setForm({ ...form, base_url: e.target.value })} /></Field>
            <Field label="API key"><input className="input font-mono text-[10.5px]" type="password" value={form.api_key} required onChange={e => setForm({ ...form, api_key: e.target.value })} /></Field>
            <Field label="Model"><input className="input font-mono text-[10.5px]" value={form.model} onChange={e => setForm({ ...form, model: e.target.value })} /></Field>
            {err && <p className="text-[10.5px]" style={{ color: 'var(--red)' }}>⚠ {err}</p>}
            <button className="btn btn-primary" type="submit">Save profile</button>
            <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>Re-submitting an existing name updates it.</p>
          </form>
        </Card>
      </div>
    </div>
  )
}
