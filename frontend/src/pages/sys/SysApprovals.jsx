import React from 'react'
import { useEffect, useState } from 'react'
import { api } from '../../api.js'
import { PageHeader, Card, Table, Field, Badge } from '../../components/SysKit.jsx'

const IC = { d: <path d="M8 2v3M4.5 4.5l2 2M11.5 4.5l-2 2M3 9h10M5 9v4M11 9v4" />, color: 'var(--amber)' }
export default function SysApprovals() {
  const [items, setItems] = useState(null)
  useEffect(() => { const t = setInterval(() => api.listApprovals(false).then(setItems).catch(() => {}), 4000)
    api.listApprovals(false).then(setItems).catch(() => {}); return () => clearInterval(t) }, [])
  async function decide(id, d) { try { await api.decideApproval(id, d) } catch {} }
  return (
    <div className="fade-in">
      <PageHeader icon={IC} title="Approval Records" sub="Held requests & tool calls — decide pending, review history" />
      <Table head={['#', 'Kind', 'Host / Tool', 'Detail', 'Decision', 'When']}
        rows={(items || []).map(a => [a.id,
          <Badge tone={String(a.method).startsWith('TOOL') ? 'blue' : 'amber'}>{a.method}</Badge>,
          <span className="font-mono">{a.host}</span>,
          <span className="font-mono text-[10px] truncate inline-block max-w-[280px]" style={{ color: 'var(--text-2)' }}>{a.path}</span>,
          a.decision ? <Badge tone={a.decision === 'approve' ? 'green' : 'red'}>{a.decision}</Badge>
            : <span className="flex gap-1.5">
                <button className="btn btn-primary text-[9.5px] px-2 py-0.5" onClick={() => decide(a.id, 'approve')}>Approve</button>
                <button className="btn btn-danger text-[9.5px] px-2 py-0.5" onClick={() => decide(a.id, 'deny')}>Deny</button>
              </span>,
          (a.created_at || '').replace('T', ' ').slice(0, 19)])}
        empty="No approval records" />
    </div>
  )
}
