import React, { useEffect, useState, useCallback } from 'react'
import { api } from '../api.js'
import { timeAgo } from '../utils.js'

const TYPES = ['subdomain', 'site', 'ip', 'port', 'domain', 'endpoint']
const TYPE_COLORS = {
  subdomain: 'var(--accent)', site: 'var(--green)', ip: 'var(--orange)',
  port: 'var(--amber)', domain: '#a371f7', endpoint: 'var(--text-2)',
}

function Icon({ d, size = 14 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor"
         strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{d}</svg>
  )
}
const I = {
  graph: <><circle cx="3.5" cy="4" r="1.8" /><circle cx="12.5" cy="4" r="1.8" /><circle cx="8" cy="12" r="1.8" /><path d="M3.5 5.8v1.7a2 2 0 0 0 2 2h5a2 2 0 0 0 2-2V5.8M8 9.5v.7" /></>,
  plus: <path d="M8 3v10M3 8h10" />,
  building: <><rect x="3" y="2.5" width="10" height="11" rx="1.2" /><path d="M5.5 5h5M5.5 7.5h5M5.5 10h3" /></>,
}

export default function AssetGraph() {
  const [companies, setCompanies] = useState([])
  const [assets, setAssets] = useState([])
  const [sel, setSel] = useState(null)
  const [q, setQ] = useState('')
  const [type, setType] = useState('')
  const [loading, setLoading] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setCompanies(await api.listCompanies())
      const params = {}
      if (sel) params.company_id = sel
      if (q) params.q = q
      if (type) params.type = type
      const r = await api.graphAssets(params)
      setAssets(r.items || [])
    } catch {} finally { setLoading(false) }
  }, [sel, q, type])

  useEffect(() => { load() }, [load])

  async function addCompany(e) {
    e.preventDefault()
    const name = e.target.elements.name.value.trim()
    if (!name) return
    try {
      await api.createCompany({ name })
      e.target.reset()
      load()
    } catch {}
  }

  const byType = {}
  for (const a of assets) byType[a.type] = (byType[a.type] || 0) + 1
  const selCompany = companies.find(c => c.id === sel)

  return (
    <div className="fade-in p-6">
      <div className="flex items-center gap-2.5 mb-4 flex-wrap">
        <span className="p-2 rounded-lg" style={{ background: 'var(--surface-3)', color: 'var(--green)' }}>
          <Icon d={I.graph} size={17} />
        </span>
        <div>
          <h2 className="text-[15px] font-bold leading-tight">Asset Graph</h2>
          <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
            {companies.length} companies · {assets.length} assets{selCompany ? ` · ${selCompany.name}` : ''}
          </p>
        </div>
        <div className="flex gap-2 ml-auto">
          <input className="input w-44 text-[11.5px]" placeholder="Search value…" value={q} onChange={e => setQ(e.target.value)} />
          <select className="input w-32 text-[11.5px]" value={type} onChange={e => setType(e.target.value)}>
            <option value="">All types</option>
            {TYPES.map(t => <option key={t}>{t}</option>)}
          </select>
        </div>
      </div>

      {/* type chips */}
      {!!Object.keys(byType).length && (
        <div className="flex flex-wrap gap-1.5 mb-3">
          {Object.entries(byType).sort((a, b) => b[1] - a[1]).map(([t, n]) => (
            <span key={t} className="badge text-[10px] font-mono" style={{ background: 'var(--surface-2)', color: TYPE_COLORS[t] || 'var(--text-2)' }}>
              {t} · {n}
            </span>
          ))}
        </div>
      )}

      <div className="grid gap-4" style={{ gridTemplateColumns: '250px 1fr' }}>
        {/* company sidebar */}
        <div className="flex flex-col gap-2.5 min-w-0">
          <form onSubmit={addCompany} className="flex gap-1.5">
            <input name="name" className="input text-[11.5px]" placeholder="New company…" />
            <button className="btn btn-accent px-2.5" type="submit" title="Add"><Icon d={I.plus} /></button>
          </form>
          <div className="card overflow-y-auto flex-1" style={{ padding: 0, maxHeight: '62vh' }}>
            <div className="card-header text-[10px] flex items-center gap-1.5" style={{ padding: '10px 12px' }}>
              <Icon d={I.building} size={12} /> Companies
            </div>
            <div onClick={() => setSel(null)}
                 className="px-3 py-2 cursor-pointer border-b text-[11.5px] font-medium transition-colors"
                 style={{ borderColor: 'var(--border)', background: !sel ? 'var(--surface-3)' : 'transparent' }}>
              All companies
            </div>
            {companies.map(c => (
              <div key={c.id} onClick={() => setSel(c.id)}
                   className="px-3 py-2 cursor-pointer border-b transition-colors"
                   style={{ borderColor: 'var(--border)', background: sel === c.id ? 'var(--surface-3)' : 'transparent' }}
                   onMouseEnter={e => { if (sel !== c.id) e.currentTarget.style.background = 'var(--surface-2)' }}
                   onMouseLeave={e => { if (sel !== c.id) e.currentTarget.style.background = 'transparent' }}>
                <div className="text-[11.5px] font-medium truncate">{c.name}</div>
                <div className="text-[9.5px] font-mono" style={{ color: 'var(--text-3)' }}>
                  {c.asset_count} assets · {Object.entries(c.by_type || {}).slice(0, 3).map(([t, n]) => `${t}:${n}`).join(' ')}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* assets table */}
        <div className="card overflow-auto" style={{ padding: 0, maxHeight: '66vh' }}>
          <table className="w-full text-[11.5px]" style={{ borderCollapse: 'collapse' }}>
            <thead>
              <tr className="text-left text-[9.5px] uppercase tracking-wider sticky top-0"
                  style={{ color: 'var(--text-3)', background: 'var(--surface)' }}>
                {['Type', 'Value', 'Meta', 'Source', 'Seen'].map(h => (
                  <th className="px-3 py-2.5 font-semibold" style={{ borderBottom: '1px solid var(--border)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading && !assets.length && (
                <tr><td colSpan={5} className="px-3 py-8 text-center" style={{ color: 'var(--text-3)' }}>loading…</td></tr>
              )}
              {assets.map(a => (
                <tr key={a.id} className="transition-colors hover:bg-[var(--surface-2)]"
                    style={{ borderBottom: '1px solid var(--border)' }}>
                  <td className="px-3 py-2">
                    <span className="badge text-[9.5px] font-mono" style={{ background: 'var(--surface-2)', color: TYPE_COLORS[a.type] || 'var(--text-2)' }}>
                      {a.type}
                    </span>
                  </td>
                  <td className="px-3 py-2 font-mono">{a.value}</td>
                  <td className="px-3 py-2 max-w-[320px] truncate" style={{ color: 'var(--text-2)' }}>
                    {a.meta?.title || (a.meta?.tech || []).join(', ') ||
                      (a.meta?.port ? `port ${a.meta.port}` : '')}
                  </td>
                  <td className="px-3 py-2 font-mono text-[10px]" style={{ color: 'var(--text-3)' }}>{a.source}</td>
                  <td className="px-3 py-2 text-[10px]" style={{ color: 'var(--text-3)' }}>{timeAgo(a.created_at)}</td>
                </tr>
              ))}
              {!loading && !assets.length && (
                <tr><td colSpan={5} className="px-3 py-10 text-center text-[11.5px]" style={{ color: 'var(--text-3)' }}>
                  No assets yet — run a workflow (findings auto-ingest into the graph) or add a company + asset manually.
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
