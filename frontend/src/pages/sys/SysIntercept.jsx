import React from 'react'
import { useEffect, useState } from 'react'
import { api } from '../../api.js'
import { PageHeader, Card, Table, Field, Badge } from '../../components/SysKit.jsx'

const IC = { d: <path d="M8 1.5 13.5 4v4c0 3.5-2.5 5.5-5.5 6.5C5 13.5 2.5 11.5 2.5 8V4zM5.5 8l1.8 1.8 3.2-3.6" />, color: 'var(--red)' }
export default function SysIntercept() {
  const [rules, setRules] = useState(null)
  const [form, setForm] = useState({ tool_pattern: '', input_pattern: '', action: 'ask' })
  const load = () => api.agentRules().then(setRules).catch(() => {})
  useEffect(() => { load() }, [])
  async function add(e) { e.preventDefault(); await api.createAgentRule(form); setForm({ tool_pattern: '', input_pattern: '', action: 'ask' }); load() }
  return (
    <div className="fade-in p-6">
      <PageHeader icon={IC} title="Interception Rules" sub="Gate agent tool calls — allow / deny / ask (ask parks the call until approved)" />
      <div className="grid gap-4" style={{ gridTemplateColumns: '1fr 340px' }}>
        <Table head={['#', 'Tool pattern', 'Input pattern', 'Action', '']}
          rows={(rules || []).map(r => [r.id, <span className="font-mono">{r.tool_pattern}</span>,
            <span className="font-mono text-[10.5px]" style={{ color: 'var(--text-2)' }}>{r.input_pattern || '(any)'}</span>,
            <Badge tone={r.action === 'deny' ? 'red' : r.action === 'ask' ? 'amber' : 'green'}>{r.action}</Badge>,
            <button className="btn btn-danger text-[10px] px-2 py-1" onClick={async () => { await api.deleteAgentRule(r.id); load() }}>Delete</button>])}
          empty="No rules" />
        <Card>
          <form onSubmit={add} className="flex flex-col gap-2.5">
            <Field label="Tool pattern (substring or re:regex)"><input className="input font-mono text-[10.5px]" placeholder="launch_run" value={form.tool_pattern} required onChange={e => setForm({ ...form, tool_pattern: e.target.value })} /></Field>
            <Field label="Input contains (optional)"><input className="input font-mono text-[10.5px]" placeholder="--deep" value={form.input_pattern} onChange={e => setForm({ ...form, input_pattern: e.target.value })} /></Field>
            <Field label="Action">
              <select className="input text-[11px]" value={form.action} onChange={e => setForm({ ...form, action: e.target.value })}>
                <option value="ask">ask — require approval</option>
                <option value="deny">deny — block</option>
                <option value="allow">allow — pass through</option>
              </select>
            </Field>
            <button className="btn btn-primary" type="submit">Add rule</button>
          </form>
        </Card>
      </div>
    </div>
  )
}
