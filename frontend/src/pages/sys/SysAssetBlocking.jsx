import React from 'react'
import { useEffect, useState } from 'react'
import { api } from '../../api.js'
import { PageHeader, Card, Table, Field, Badge } from '../../components/SysKit.jsx'

const IC = { d: <><circle cx="8" cy="8" r="6" /><path d="M3.8 3.8l8.4 8.4" /></>, color: 'var(--red)' }
export default function SysAssetBlocking() {
  const [rules, setRules] = useState(null)
  const [form, setForm] = useState({ pattern: '', action: 'block' })
  const load = () => api.listRules().then(setRules).catch(() => {})
  useEffect(() => { load() }, [])
  async function add(e) { e.preventDefault(); await api.createRule(form); setForm({ pattern: '', action: 'block' }); load() }
  return (
    <div className="fade-in p-6">
      <PageHeader icon={IC} title="Asset blocking" sub="Proxy-level traffic rules — block / hold / flag hosts matching a pattern (e.g. .gov, .edu)" />
      <div className="grid gap-4" style={{ gridTemplateColumns: '1fr 340px' }}>
        <Table head={['#', 'Pattern', 'Action', '']}
          rows={(rules || []).map(r => [r.id, <span className="font-mono">{r.pattern}</span>,
            <Badge tone={r.action === 'block' ? 'red' : r.action === 'hold' ? 'amber' : 'blue'}>{r.action}</Badge>,
            <button className="btn btn-danger text-[10px] px-2 py-1" onClick={async () => { await api.deleteRule(r.id); load() }}>Delete</button>])}
          empty="No blocking rules" />
        <Card>
          <form onSubmit={add} className="flex flex-col gap-2.5">
            <Field label="Host pattern (substring)"><input className="input font-mono text-[10.5px]" placeholder=".gov" value={form.pattern} required onChange={e => setForm({ ...form, pattern: e.target.value })} /></Field>
            <Field label="Action">
              <select className="input text-[11px]" value={form.action} onChange={e => setForm({ ...form, action: e.target.value })}>
                <option value="block">block — 403 immediately</option>
                <option value="hold">hold — require approval</option>
                <option value="flag">flag — allow + mark</option>
              </select>
            </Field>
            <button className="btn btn-primary" type="submit">Add rule</button>
          </form>
        </Card>
      </div>
    </div>
  )
}
