import React from 'react'
import { useEffect, useState } from 'react'
import { api } from '../../api.js'
import { PageHeader, Card, Table, Field, Badge } from '../../components/SysKit.jsx'

const IC = { d: <><circle cx="8" cy="8" r="6" /><circle cx="8" cy="8" r="2" /></>, color: 'var(--green)' }
export default function SysAgents() {
  const [prompt, setPrompt] = useState(null)
  useEffect(() => { api.agentPrompt().then(p => setPrompt(p.system_prompt)).catch(() => {}) }, [])
  return (
    <div className="fade-in">
      <PageHeader icon={IC} title="Agents" sub="The recon agent persona — the operating discipline baked into every conversation" />
      <Card>
        <pre className="whitespace-pre-wrap text-[11.5px] leading-relaxed" style={{ color: 'var(--text-2)' }}>
          {prompt || 'loading…'}
        </pre>
      </Card>
    </div>
  )
}
