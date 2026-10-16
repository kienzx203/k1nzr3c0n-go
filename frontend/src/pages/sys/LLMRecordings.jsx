import React from 'react'
import { useEffect, useState } from 'react'
import { api } from '../../api.js'
import { PageHeader, Card, Table, Field, Badge } from '../../components/SysKit.jsx'

const IC = { d: <path d="M2 5h8M2 8h12M2 11h6M11 11l3-3M14 8l-3-3" />, color: 'var(--amber)' }
export default function LLMRecordings() {
  const [rows, setRows] = useState(null)
  const [totals, setTotals] = useState(null)
  useEffect(() => { api.llmUsageList(200).then(setRows).catch(() => {}); api.llmUsage().then(setTotals).catch(() => {}) }, [])
  return (
    <div className="fade-in p-6">
      <PageHeader icon={IC} title="LLM Recordings" sub="Usage ledger — every agent turn metered"
        right={totals ? [<Badge key="t" tone="blue">{totals.turns} turns</Badge>, <Badge key="k" tone="amber">{totals.total_tokens} tokens</Badge>] : []} />
      <Table head={['#', 'Profile', 'Conversation', 'Prompt', 'Completion', 'Total', 'When']}
        rows={(rows || []).map(u => [u.id, u.profile_id, u.conversation_id, u.prompt_tokens, u.completion_tokens,
          <b style={{ color: 'var(--accent)' }}>{u.total_tokens}</b>,
          (u.created_at || '').replace('T', ' ').slice(0, 19)])}
        empty="No LLM calls recorded yet" />
    </div>
  )
}
