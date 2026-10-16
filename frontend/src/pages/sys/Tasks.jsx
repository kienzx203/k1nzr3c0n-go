import React from 'react'
import { useEffect, useState } from 'react'
import { api } from '../../api.js'
import { PageHeader, Card, Table, Field, Badge } from '../../components/SysKit.jsx'

const IC = { d: <path d="M3 3h6v6H3zM7 13h6v-2l3 3-3 3v-2H7z" />, color: 'var(--green)' }
export default function Tasks() {
  const [convs, setConvs] = useState([])
  const [msgs, setMsgs] = useState(null)
  const [sel, setSel] = useState(null)
  useEffect(() => { api.listConvs().then(c => setConvs(c.filter(x => (x.title || '').startsWith('autopilot')))).catch(() => {}) }, [])
  useEffect(() => { if (sel) api.convMessages(sel).then(setMsgs).catch(() => {}) }, [sel])
  return (
    <div className="fade-in">
      <PageHeader icon={IC} title="Tasks" sub="Autonomous engagement campaigns — plan → execute → analyze" />
      <div className="grid gap-4" style={{ gridTemplateColumns: '280px 1fr' }}>
        <Card pad={false}>
          <div className="card-header px-3 py-2.5 text-[10px]">Engagements</div>
          {convs.map(c => (
            <div key={c.id} onClick={() => setSel(c.id)} className="px-3 py-2 cursor-pointer border-b text-[11.5px] truncate"
                 style={{ borderColor: 'var(--border)', background: sel === c.id ? 'var(--surface-3)' : 'transparent' }}>
              {c.title}
            </div>
          ))}
          {!convs.length && <div className="px-3 py-4 text-[11px]" style={{ color: 'var(--text-3)' }}>
            No autonomous tasks yet — start one from Chat → Autopilot.</div>}
        </Card>
        <Card pad={false}>
          <div className="card-header px-3 py-2.5 text-[10px]">Phases</div>
          <div className="p-3 flex flex-col gap-2">
            {(msgs || []).map((m, i) => (
              <div key={i} className="text-[11.5px] whitespace-pre-wrap"
                   style={{ color: m.role === 'user' ? 'var(--text)' : 'var(--text-2)' }}>
                {m.role === 'user' ? '▸ ' : ''}{m.content}
              </div>
            ))}
            {!msgs && <div className="text-[11px]" style={{ color: 'var(--text-3)' }}>Select an engagement.</div>}
          </div>
        </Card>
      </div>
    </div>
  )
}
