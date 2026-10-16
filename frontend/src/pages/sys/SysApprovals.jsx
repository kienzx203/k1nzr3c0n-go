import React, { useEffect, useState } from 'react'
import { api } from '../../api.js'
import { PageHeader, Card, Table, Badge } from '../../components/SysKit.jsx'

const IC = { d: <path d="M8 2v3M4.5 4.5l2 2M11.5 4.5l-2 2M3 9h10M5 9v4M11 9v4" />, color: 'var(--amber)' }
export default function SysApprovals() {
  const [items, setItems] = useState(null)
  const [detail, setDetail] = useState(null)
  const refresh = () => api.listApprovals(false).then(setItems).catch(() => {})
  useEffect(() => { refresh(); const t = setInterval(refresh, 4000); return () => clearInterval(t) }, [])
  async function decide(id, d) { try { await api.decideApproval(id, d); refresh(); if (detail?.id === id) setDetail(null) } catch {} }
  async function open(id) { try { setDetail(await api.approvalDetail(id)) } catch {} }

  return (
    <div className="fade-in p-6">
      <PageHeader icon={IC} title="Approval Records" sub="Held requests & tool calls — decide pending, review full detail" />
      <div className="grid gap-4" style={{ gridTemplateColumns: detail ? '1fr 1fr' : '1fr' }}>
        <Table head={['#', 'Kind', 'Host / Tool', 'Detail', 'Decision', 'When']}
          rows={(items || []).map(a => [a.id,
            <Badge tone={String(a.method).startsWith('TOOL') ? 'blue' : 'amber'}>{a.method}</Badge>,
            <span className="font-mono cursor-pointer hover:underline" style={{ color: 'var(--accent)' }} onClick={() => open(a.id)}>{a.host}</span>,
            <span className="font-mono text-[10px] truncate inline-block max-w-[280px] cursor-pointer" style={{ color: 'var(--text-2)' }} onClick={() => open(a.id)}>{a.path}</span>,
            a.decision ? <Badge tone={a.decision === 'approve' ? 'green' : 'red'}>{a.decision}</Badge>
              : <span className="flex gap-1.5">
                  <button className="btn btn-primary text-[9.5px] px-2 py-0.5" onClick={() => decide(a.id, 'approve')}>Approve</button>
                  <button className="btn btn-danger text-[9.5px] px-2 py-0.5" onClick={() => decide(a.id, 'deny')}>Deny</button>
                </span>,
            (a.created_at || '').replace('T', ' ').slice(0, 19)])}
          empty="No approval records" />

        {detail && (
          <Card pad={false}>
            <div className="card-header flex-wrap gap-2">
              <Badge tone="amber">{detail.method}</Badge>
              <span className="font-mono text-[11.5px] truncate">{detail.host}{detail.path}</span>
              <div className="ml-auto flex gap-1.5">
                {!detail.decision && <>
                  <button className="btn btn-primary text-[10px] px-2 py-1" onClick={() => decide(detail.id, 'approve')}>Approve</button>
                  <button className="btn btn-danger text-[10px] px-2 py-1" onClick={() => decide(detail.id, 'deny')}>Deny</button>
                </>}
                <button className="btn btn-ghost text-[10px] px-2 py-1" onClick={() => setDetail(null)}>✕</button>
              </div>
            </div>
            <div className="p-3.5">
              <p className="text-[9.5px] font-bold uppercase tracking-wider mb-1.5" style={{ color: 'var(--accent)' }}>── Request dump ──</p>
              <pre className="m-0 whitespace-pre-wrap text-[10.5px] leading-relaxed font-mono" style={{ color: 'var(--text-2)' }}>
                {detail.dump || '(no captured request body)'}
              </pre>
            </div>
          </Card>
        )}
      </div>
    </div>
  )
}
