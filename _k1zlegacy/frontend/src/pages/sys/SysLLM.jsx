import React, { useEffect, useState } from 'react'
import { api } from '../../api.js'
import { PageHeader, Card, Table, Field, Badge } from '../../components/SysKit.jsx'

const IC = { d: <path d="M8 1.5 9.5 6.5 14.5 8 9.5 9.5 8 14.5 6.5 9.5 1.5 8 6.5 6.5z" />, color: 'var(--accent)' }

const PRESETS = [
  { label: 'Z.ai General API — GLM-5.3', url: 'https://api.z.ai/api/paas/v4', model: 'glm-5.3' },
  { label: 'Z.ai Coding Plan — GLM-5.3', url: 'https://api.z.ai/api/coding/paas/v4', model: 'glm-5.3' },
  { label: 'Z.ai General API — GLM-4.7', url: 'https://api.z.ai/api/paas/v4', model: 'glm-4.7' },
  { label: 'Z.ai Free — GLM-4.5-flash', url: 'https://api.z.ai/api/paas/v4', model: 'glm-4.5-flash' },
  { label: 'BigModel (CN) — GLM-4.6', url: 'https://open.bigmodel.cn/api/paas/v4', model: 'glm-4.6' },
  { label: 'Ollama — same machine', url: 'http://127.0.0.1:11434/v1', model: 'llama3.1', ollama: true },
  { label: 'Ollama — host from Docker', url: 'http://host.docker.internal:11434/v1', model: 'llama3.1', ollama: true },
  { label: 'Ollama — docker compose (local-llm)', url: 'http://ollama:11434/v1', model: 'llama3.1', ollama: true },
  { label: 'Custom…', url: '', model: '' },
]

export default function SysLLM() {
  const [profiles, setProfiles] = useState(null)
  const [form, setForm] = useState({ name: '', base_url: PRESETS[0].url, api_key: '', model: PRESETS[0].model })
  const [isOllama, setIsOllama] = useState(false)
  const [ollamaModels, setOllamaModels] = useState([])
  const [loadingModels, setLoadingModels] = useState(false)
  const [localOnly, setLocalOnly] = useState(false)
  const [err, setErr] = useState('')

  const load = () => api.listLLM().then(setProfiles).catch(() => {})
  useEffect(() => { load(); api.getLocalLLM().then(r => setLocalOnly(!!r.enabled)).catch(() => {}) }, [])

  function pickPreset(label) {
    const p = PRESETS.find(x => x.label === label) || PRESETS[0]
    setForm(f => ({ ...f, base_url: p.url, model: p.model || f.model }))
    setIsOllama(!!p.ollama)
    setOllamaModels([])
  }
  async function loadModels() {
    setLoadingModels(true); setErr('')
    try {
      const r = await api.ollamaModels(form.base_url)
      setOllamaModels(r.models || [])
      if (r.models?.length) setForm(f => ({ ...f, model: r.models[0] }))
    } catch (e) { setErr(e.message) } finally { setLoadingModels(false) }
  }
  async function create(e) {
    e.preventDefault(); setErr('')
    const body = { ...form }
    if (isOllama && !body.api_key) body.api_key = 'ollama' // keyless; backend requires non-empty
    try { await api.createLLM(body); setForm({ ...form, api_key: '' }); load() } catch (e2) { setErr(e2.message) }
  }
  async function toggleLocal() {
    const next = !localOnly; setLocalOnly(next)
    try { await api.setLocalLLM(next) } catch { setLocalOnly(!next) }
  }

  return (
    <div className="fade-in p-6">
      <PageHeader icon={IC} title="LLM Profiles" sub="Failover chain — the agent falls back to the next profile on 401/429/quota/5xx"
        right={
          <button className="btn text-[11px]" onClick={toggleLocal} title="Restrict LLM connections to local/trusted addresses">
            <span className="w-2 h-2 rounded-full" style={{ background: localOnly ? 'var(--green)' : 'var(--text-3)' }} />
            Local-only LLM network: {localOnly ? 'ON' : 'OFF'}
          </button>
        } />
      <div className="grid gap-4 mb-4" style={{ gridTemplateColumns: '1fr 360px' }}>
        <Table head={['#', 'Name', 'Model', 'Base URL', 'Key']}
          rows={(profiles || []).map(p => [p.id, p.name, <Badge tone="blue">{p.model}</Badge>,
            <span className="font-mono text-[10px]">{p.base_url}</span>,
            <span className="font-mono text-[10px]" style={{ color: 'var(--text-3)' }}>{p.api_key_masked}</span>])}
          empty="No profiles" />
        <Card>
          <form onSubmit={create} className="flex flex-col gap-2.5">
            <Field label="Name"><input className="input" value={form.name} required onChange={e => setForm({ ...form, name: e.target.value })} /></Field>
            <Field label="Preset">
              <select className="input text-[11px]" onChange={e => pickPreset(e.target.value)} defaultValue={PRESETS[0].label}>
                {PRESETS.map(p => <option key={p.label} value={p.label}>{p.label}</option>)}
              </select>
            </Field>
            <Field label="Base URL"><input className="input font-mono text-[10.5px]" value={form.base_url} onChange={e => setForm({ ...form, base_url: e.target.value })} /></Field>
            {isOllama && (
              <div className="flex gap-2 items-end">
                <Field label="Model (from Ollama)">
                  <select className="input font-mono text-[10.5px]" value={form.model} onChange={e => setForm({ ...form, model: e.target.value })}>
                    {!ollamaModels.length && <option value={form.model}>{form.model}</option>}
                    {ollamaModels.map(m => <option key={m} value={m}>{m}</option>)}
                  </select>
                </Field>
                <button type="button" className="btn text-[11px]" onClick={loadModels} disabled={loadingModels}>
                  {loadingModels ? '…' : '↻ Load'}
                </button>
              </div>
            )}
            {!isOllama && <Field label="Model"><input className="input font-mono text-[10.5px]" value={form.model} onChange={e => setForm({ ...form, model: e.target.value })} /></Field>}
            <Field label={isOllama ? 'API key (not needed for Ollama)' : 'API key'}>
              <input className="input font-mono text-[10.5px]" type="password" value={form.api_key} required={!isOllama}
                     placeholder={isOllama ? 'leave empty' : ''} onChange={e => setForm({ ...form, api_key: e.target.value })} />
            </Field>
            {err && <p className="text-[10.5px]" style={{ color: 'var(--red)' }}>⚠ {err}</p>}
            <button className="btn btn-primary" type="submit">Save profile</button>
            <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>Re-submitting an existing name updates it.</p>
          </form>
        </Card>
      </div>
    </div>
  )
}
