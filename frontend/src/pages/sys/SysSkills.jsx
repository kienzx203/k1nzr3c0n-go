import React from 'react'
import { useEffect, useState } from 'react'
import { api } from '../../api.js'
import { PageHeader, Card, Table, Field, Badge } from '../../components/SysKit.jsx'

const IC = { d: <path d="M8 1.5 13.5 4v4c0 3.5-2.5 5.5-5.5 6.5C5 13.5 2.5 11.5 2.5 8V4z" />, color: 'var(--green)' }
export default function SysSkills() {
  const [items, setItems] = useState(null)
  useEffect(() => { api.skillsList().then(setItems).catch(() => {}) }, [])
  return (
    <div className="fade-in p-6">
      <PageHeader icon={IC} title="Skills" sub="SKILL.md playbooks the agent loads via list_skills / load_skill" />
      <Table head={['Name', 'Description', 'Instructions']}
        rows={(items || []).map(s => [<Badge tone="blue">{s.name}</Badge>,
          <span style={{ color: 'var(--text-2)' }}>{s.description}</span>,
          `${s.instructions_len} chars`])}
        empty="No skills found under <base>/skills/" />
    </div>
  )
}
