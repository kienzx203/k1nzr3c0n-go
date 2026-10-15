import React, { useEffect, useState } from 'react'

const API = '/api/v1'
const TYPES = ['subdomain', 'site', 'ip', 'port', 'domain', 'endpoint']

export default function AssetGraph() {
  const [companies, setCompanies] = useState([])
  const [assets, setAssets] = useState([])
  const [sel, setSel] = useState(null) // selected company id
  const [q, setQ] = useState('')
  const [type, setType] = useState('')

  useEffect(() => { load() }, [sel, q, type])

  async function load() {
    const rc = await fetch(`${API}/companies`)
    setCompanies(await rc.json())
    const params = new URLSearchParams()
    if (sel) params.set('company_id', sel)
    if (q) params.set('q', q)
    if (type) params.set('type', type)
    const ra = await fetch(`${API}/graph/assets?${params}`)
    setAssets((await ra.json()).items || [])
  }

  async function addCompany(e) {
    e.preventDefault()
    const name = e.target.elements.name.value.trim()
    if (!name) return
    await fetch(`${API}/companies`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name }),
    })
    e.target.reset()
    load()
  }

  const byType = {}
  for (const a of assets) byType[a.type] = (byType[a.type] || 0) + 1

  return (
    <div>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 14, flexWrap: 'wrap' }}>
        <h2 style={{ margin: 0 }}>Asset Graph</h2>
        <span style={{ color: '#6e7681', fontSize: 12 }}>
          {assets.length} assets {sel ? `· ${companies.find(c => c.id === sel)?.name}` : '· all companies'}
          {Object.entries(byType).map(([t, n]) => ` · ${t}:${n}`).join('')}
        </span>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
          <input placeholder="search value…" value={q} onChange={e => setQ(e.target.value)} />
          <select value={type} onChange={e => setType(e.target.value)}>
            <option value="">all types</option>
            {TYPES.map(t => <option key={t}>{t}</option>)}
          </select>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '260px 1fr', gap: 14 }}>
        <div>
          <form onSubmit={addCompany} style={{ display: 'flex', gap: 6, marginBottom: 10 }}>
            <input name="name" placeholder="new company / target" style={{ flex: 1 }} />
            <button className="btn" type="submit">+</button>
          </form>
          <div style={{ border: '1px solid #232a3a', borderRadius: 8 }}>
            <div onClick={() => setSel(null)}
                 style={{ padding: 10, cursor: 'pointer', borderBottom: '1px solid #1b2230',
                          fontWeight: !sel ? 700 : 400 }}>
              All companies
            </div>
            {companies.map(c => (
              <div key={c.id} onClick={() => setSel(c.id)}
                   style={{ padding: 10, cursor: 'pointer', borderBottom: '1px solid #1b2230',
                            background: sel === c.id ? '#16281e' : 'transparent' }}>
                <div style={{ fontWeight: sel === c.id ? 700 : 400 }}>{c.name}</div>
                <div style={{ fontSize: 11, color: '#6e7681' }}>
                  {c.asset_count} assets {Object.entries(c.by_type || {}).slice(0, 3).map(([t, n]) => `· ${t}:${n}`).join(' ')}
                </div>
              </div>
            ))}
          </div>
        </div>

        <div style={{ border: '1px solid #232a3a', borderRadius: 8, maxHeight: '70vh', overflowY: 'auto' }}>
          <table style={{ width: '100%', fontSize: 12, borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ textAlign: 'left', color: '#8b949e', position: 'sticky', top: 0, background: '#0d1117' }}>
                <th style={{ padding: 8 }}>Type</th><th>Value</th><th>Meta</th><th>Source</th>
              </tr>
            </thead>
            <tbody>
              {assets.map(a => (
                <tr key={a.id} style={{ borderBottom: '1px solid #1b2230' }}>
                  <td style={{ padding: 7 }}>
                    <span style={{ background: '#1f6feb33', padding: '2px 8px', borderRadius: 10, fontSize: 11 }}>{a.type}</span>
                  </td>
                  <td style={{ fontFamily: 'inherit' }}>{a.value}</td>
                  <td style={{ color: '#8b949e', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {a.meta && a.meta.title ? a.meta.title : a.meta && a.meta.tech ? (a.meta.tech || []).join(', ') : ''}
                  </td>
                  <td style={{ color: '#6e7681' }}>{a.source}</td>
                </tr>
              ))}
              {!assets.length && (
                <tr><td colSpan={4} style={{ padding: 14, color: '#6e7681' }}>
                  Chưa có asset — chạy workflow (findings tự nạp vào graph) hoặc thêm thủ công.
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
