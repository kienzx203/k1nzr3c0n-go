import React from 'react'
import { useEffect, useState } from 'react'
import { api } from '../../api.js'
import { PageHeader, Card, Table, Field, Badge } from '../../components/SysKit.jsx'

const IC = { d: <path d="M2 8h4M10 8h4M6 8c0-2 1-3 2-3s2 1 2 3-1 3-2 3-2-1-2-3zM2 3l3 2M14 3l-3 2M2 13l3-2M14 13l-3-2" />, color: 'var(--green)' }
export default function AssetSync() {
  const [form, setForm] = useState({ url: '', api_key: '', scope: '' })
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)
  async function sync(e) { e.preventDefault(); setBusy(true); setResult(null)
    try { setResult(await api.syncScopeSentry(form)) } catch (e2) { setResult({ error: e2.message }) } setBusy(false) }
  return (
    <div className="fade-in p-6">
      <PageHeader icon={IC} title="Asset sync" sub="Import assets from a ScopeSentry instance into the graph" />
      <Card>
        <form onSubmit={sync} className="flex flex-col gap-3" style={{ maxWidth: 520 }}>
          <Field label="ScopeSentry URL"><input className="input font-mono text-[11px]" placeholder="https://scopesentry.example" value={form.url} onChange={e => setForm({ ...form, url: e.target.value })} /></Field>
          <Field label="API key (X-API-Key)"><input className="input font-mono text-[11px]" type="password" value={form.api_key} onChange={e => setForm({ ...form, api_key: e.target.value })} /></Field>
          <Field label="Company scope (optional graph grouping)"><input className="input text-[11px]" placeholder="acme" value={form.scope} onChange={e => setForm({ ...form, scope: e.target.value })} /></Field>
          <button className="btn btn-primary" disabled={busy || !form.url || !form.api_key}>{busy ? 'Syncing…' : 'Sync now'}</button>
        </form>
        {result && (
          <p className="mt-3 text-[12px]" style={{ color: result.error ? 'var(--red)' : 'var(--green)' }}>
            {result.error ? '⚠ ' + result.error : `✓ imported ${result.imported} assets`}
          </p>
        )}
      </Card>
    </div>
  )
}
