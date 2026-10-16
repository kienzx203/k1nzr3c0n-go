import React from 'react'
import { useEffect, useState } from 'react'
import { api } from '../../api.js'
import { PageHeader, Card, Table, Field, Badge } from '../../components/SysKit.jsx'

const IC = { d: <path d="M3 6.5C3 10 5 12 8 13.5 11 12 13 10 13 6.5L8 4z M8 13.5V15" />, color: 'var(--amber)' }
export default function SysNotifications() {
  const [n, setN] = useState(null)
  const [msg, setMsg] = useState('')
  useEffect(() => { api.notifyGet().then(setN).catch(() => {}) }, [])
  async function save(e) { e.preventDefault(); try { await api.notifyPut(n); setMsg('Saved') } catch (e2) { setMsg(e2.message) } }
  async function test() { try { await api.notifyTest(); setMsg('Test sent') } catch (e2) { setMsg(e2.message) } }
  if (!n) return null
  return (
    <div className="fade-in p-6">
      <PageHeader icon={IC} title="Notifications" sub="Discord/Slack webhook — run results, critical findings, new assets" />
      <Card>
        <form onSubmit={save} className="flex flex-col gap-3" style={{ maxWidth: 520 }}>
          <Field label="Webhook URL"><input className="input font-mono text-[11px]" placeholder="https://discord.com/api/webhooks/…" value={n.webhook_url} onChange={e => setN({ ...n, webhook_url: e.target.value })} /></Field>
          <Field label="Username (Slack-style)"><input className="input text-[11px]" value={n.username} onChange={e => setN({ ...n, username: e.target.value })} /></Field>
          <div className="flex gap-2">
            <button className="btn btn-primary" type="submit">Save</button>
            <button className="btn btn-accent" type="button" onClick={test}>Send test</button>
          </div>
          {msg && <p className="text-[11px]" style={{ color: 'var(--green)' }}>{msg}</p>}
        </form>
      </Card>
    </div>
  )
}
