import React from 'react'
import { useEffect, useState } from 'react'
import { api } from '../../api.js'
import { PageHeader, Card, Table, Field, Badge } from '../../components/SysKit.jsx'

const IC = { d: <path d="M3 4h10M3 7h7M3 10h10M3 13h5" />, color: 'var(--text-2)' }
export default function SysLogs() {
  const [items, setItems] = useState(null)
  useEffect(() => { const t = setInterval(() => api.systemLogs(200).then(setItems).catch(() => {}), 5000)
    api.systemLogs(200).then(setItems).catch(() => {}); return () => clearInterval(t) }, [])
  return (
    <div className="fade-in">
      <PageHeader icon={IC} title="Logs" sub="Recent activity — agent tool calls and run log tails" />
      <div className="card p-3 overflow-auto" style={{ maxHeight: '70vh' }}>
        {(items || []).items?.map((l, i) => (
          <div key={i} className="text-[10.5px] font-mono flex gap-2 py-0.5">
            <span style={{ color: 'var(--text-3)' }}>{String(l.ts || '').replace('T', ' ').slice(5, 19)}</span>
            <span style={{ color: l.source.startsWith('agent') ? 'var(--accent)' : 'var(--green)' }}>{l.source}</span>
            <span className="truncate" style={{ color: 'var(--text-2)' }}>{l.text}</span>
          </div>
        ))}
        {!(items || {}).items?.length && <div className="text-[11px]" style={{ color: 'var(--text-3)' }}>No activity yet</div>}
      </div>
    </div>
  )
}
