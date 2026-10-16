import React from 'react'
import { useEffect, useState } from 'react'
import { api } from '../../api.js'
import { PageHeader, Card, Table, Field, Badge } from '../../components/SysKit.jsx'

const IC = { d: <path d="M4.5 6 7 8l-2.5 2M8.5 10.5H12M1.5 2.5h13v11h-13z" />, color: 'var(--accent)' }
export default function SysToolExec() {
  const [items, setItems] = useState(null)
  useEffect(() => { const t = setInterval(() => api.agentAudit(150).then(setItems).catch(() => {}), 5000)
    api.agentAudit(150).then(setItems).catch(() => {}); return () => clearInterval(t) }, [])
  return (
    <div className="fade-in p-6">
      <PageHeader icon={IC} title="Tool executions" sub="Every agent tool call — audited, including blocked attempts" />
      <Table head={['#', 'Tool', 'Arguments', 'Result', 'When']}
        rows={(items || []).map(a => [a.id,
          <span className="font-mono" style={{ color: a.blocked ? 'var(--red)' : 'var(--accent)' }}>{a.tool}</span>,
          <span className="font-mono text-[10px] truncate inline-block max-w-[240px]">{a.args}</span>,
          <span className="font-mono text-[10px] truncate inline-block max-w-[280px]"
                style={{ color: a.blocked ? 'var(--red)' : 'var(--text-2)' }}>{a.blocked ? '⛔ ' + a.result : a.result}</span>,
          (a.created_at || '').replace('T', ' ').slice(5, 19)])}
        empty="No tool executions yet" />
    </div>
  )
}
