import React from 'react'
import { useEffect, useState } from 'react'
import { api } from '../../api.js'
import { PageHeader, Card, Table, Field, Badge } from '../../components/SysKit.jsx'

const IC = { d: <path d="M2 4.5h4l1.5 2h6.5v7H2z" />, color: 'var(--orange)' }
export default function Workspace() {
  const [items, setItems] = useState(null)
  const [busy, setBusy] = useState(false)
  const load = () => api.workspaceList().then(setItems).catch(() => setItems([]))
  useEffect(() => { load() }, [])
  async function upload(e) {
    const f = e.target.files[0]; if (!f) return
    setBusy(true)
    const fd = new FormData(); fd.append('file', f)
    await api.workspaceUpload(fd); setBusy(false); load()
  }
  return (
    <div className="fade-in">
      <PageHeader icon={IC} title="Workspace" sub="Shared artifacts — browse, upload, download"
        right={<label className="btn btn-primary text-[11px] cursor-pointer">
          {busy ? 'Uploading…' : '+ Upload'}<input type="file" hidden onChange={upload} /></label>} />
      <Table head={['Name', 'Size', 'Actions']}
        rows={(items || []).map(f => [
          <span className="font-mono" style={{ color: 'var(--accent)' }}>{f.name}</span>,
          f.is_dir ? '—' : `${(f.size / 1024).toFixed(1)} KB`,
          <span className="flex gap-2">
            {!f.is_dir && <a className="btn text-[10px] px-2 py-1" href={`/api/v1/workspace/${encodeURIComponent(f.name)}`}>Download</a>}
            <button className="btn btn-danger text-[10px] px-2 py-1"
                    onClick={async () => { await api.workspaceDelete(f.name); load() }}>Delete</button>
          </span>])}
        empty="No artifacts yet" />
    </div>
  )
}
