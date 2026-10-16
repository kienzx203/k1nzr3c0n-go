import React from 'react'
import { useEffect, useState } from 'react'
import { api } from '../../api.js'
import { PageHeader, Card, Table, Field, Badge } from '../../components/SysKit.jsx'

const IC = { d: <><rect x="2" y="2.5" width="12" height="4" rx="1" /><rect x="2" y="9.5" width="12" height="4" rx="1" /><path d="M5 4.5v0M5 11.5v0" /></>, color: 'var(--orange)' }
export default function SysMCP() {
  const [items, setItems] = useState(null)
  const [form, setForm] = useState({ name: '', command: '', args: '' })
  const [err, setErr] = useState('')
  const load = () => api.listMCP().then(setItems).catch(() => {})
  useEffect(() => { load() }, [])
  async function add(e) { e.preventDefault(); setErr('')
    try { await api.createMCP({ name: form.name, command: form.command, args: form.args.split(/\s+/).filter(Boolean) }); setForm({ name: '', command: '', args: '' }); load() } catch (e2) { setErr(e2.message) } }
  return (
    <div className="fade-in p-6">
      <PageHeader icon={IC} title="MCP Servers" sub="External tool servers merged into the agent as mcp_<server>_<tool>" />
      <div className="grid gap-4" style={{ gridTemplateColumns: '1fr 340px' }}>
        <Table head={['#', 'Name', 'Command', 'Enabled', 'Actions']}
          rows={(items || []).map(m => [m.id, <Badge tone="blue">{m.name}</Badge>,
            <span className="font-mono text-[10.5px]">{m.command} {(m.args || []).join(' ')}</span>,
            m.enabled ? <Badge tone="green">on</Badge> : <Badge tone="gray">off</Badge>,
            <button className="btn btn-danger text-[10px] px-2 py-1" onClick={async () => { await api.deleteMCP(m.id); load() }}>Delete</button>])}
          empty="No MCP servers" />
        <Card>
          <form onSubmit={add} className="flex flex-col gap-2.5">
            <Field label="Name"><input className="input" value={form.name} required onChange={e => setForm({ ...form, name: e.target.value })} /></Field>
            <Field label="Command"><input className="input font-mono text-[10.5px]" placeholder="npx" value={form.command} required onChange={e => setForm({ ...form, command: e.target.value })} /></Field>
            <Field label="Arguments (space-separated)"><input className="input font-mono text-[10.5px]" placeholder="-y @some/mcp-server" value={form.args} onChange={e => setForm({ ...form, args: e.target.value })} /></Field>
            {err && <p className="text-[10.5px]" style={{ color: 'var(--red)' }}>⚠ {err}</p>}
            <button className="btn btn-primary" type="submit">Add server</button>
            <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>Servers connect per chat turn; tools appear automatically.</p>
          </form>
        </Card>
      </div>
    </div>
  )
}
