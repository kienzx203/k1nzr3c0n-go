import React, { useEffect, useState } from 'react'
import { api } from '../api.js'

/* SecurityTrails intel viewer — everything `securitytrails_fetch.py --mode all`
   collected for the run's target. List files get search + per-domain actions;
   JSON files render as structured cards instead of raw text. */

const FILE_META = {
  'p_securitytrails.txt':   { label: 'Subdomains',        kind: 'list', icon: '◈', hint: 'all subdomains — feeds the recon pipeline' },
  'st_subdomains.txt':      { label: 'Subdomains (raw)',  kind: 'list', icon: '◈', hint: 'raw ST subdomain list' },
  'st_dns_records.txt':     { label: 'DNS Records',       kind: 'list', icon: '≡', hint: 'NS/MX/A/AAAA/TXT — current + historical' },
  'st_domain_info.json':    { label: 'Domain Info',       kind: 'json', icon: 'ℹ', hint: 'current domain snapshot' },
  'st_whois.json':          { label: 'WHOIS',             kind: 'json', icon: '⊙', hint: 'current WHOIS record' },
  'st_whois_history.json':  { label: 'WHOIS History',     kind: 'json', icon: '⧗', hint: 'every WHOIS change ST observed' },
  'st_ssl.json':            { label: 'SSL Certificates',  kind: 'json', icon: '🔒', hint: 'TLS certs observed for the domain' },
  'st_associated.txt':      { label: 'Associated',        kind: 'list', icon: '⧉', hint: 'ST-linked domains (same company/infra) — intel leads', registrable: true },
  'st_pivot_domains.txt':   { label: 'NS/MX Pivot',       kind: 'list', icon: '⇄', hint: 'domains sharing NS/MX — intel leads, NOT auto-scanned', registrable: true },
}

const LIST_CAP = 400

function JsonView({ data }) {
  if (data == null || (typeof data === 'object' && Object.keys(data).length === 0)) {
    return <p className="text-[11px] italic p-4" style={{ color: 'var(--text-3)' }}>(no data)</p>
  }
  const renderVal = (v) => {
    if (v == null) return <span style={{ color: 'var(--text-3)' }}>—</span>
    if (typeof v === 'object') return (
      <pre className="text-[10px] font-mono mt-1 p-2 rounded overflow-x-auto"
           style={{ background: 'var(--bg-soft)', color: 'var(--text-2)', border: '1px solid var(--border)' }}>
        {JSON.stringify(v, null, 2)}
      </pre>
    )
    return <span className="font-mono text-[11px]" style={{ color: 'var(--text)' }}>{String(v)}</span>
  }
  const entries = Object.entries(data)
  return (
    <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-3">
      {entries.map(([k, v]) => (
        <div key={k} className="min-w-0">
          <p className="text-[9px] font-bold uppercase tracking-wider mb-0.5" style={{ color: 'var(--text-3)' }}>{k}</p>
          {renderVal(v)}
        </div>
      ))}
    </div>
  )
}

export default function STIntelPanel({ runId }) {
  const [files, setFiles] = useState([])
  const [selected, setSelected] = useState(null)
  const [content, setContent] = useState(null)
  const [json, setJson] = useState(null)
  const [loading, setLoading] = useState(false)
  const [checked, setChecked] = useState(false)
  const [query, setQuery] = useState('')
  const [msg, setMsg] = useState('')

  useEffect(() => {
    api.getFiles(runId)
      .then(list => {
        const intel = (list || []).filter(f =>
          f.name.startsWith('st_') || f.name === 'p_securitytrails.txt')
        const seen = new Set()
        const uniq = intel.filter(f => {
          const key = f.name === 'st_subdomains.txt' ? 'subs' : f.name
          if (seen.has(key)) return false
          seen.add(key)
          return true
        })
        setFiles(uniq)
        const firstWithData = uniq.find(f => f.size > 3) || uniq[0]
        if (firstWithData) setSelected(firstWithData.path)
        setChecked(true)
      })
      .catch(() => setChecked(true))
  }, [runId])

  useEffect(() => {
    if (!selected) return
    setLoading(true)
    setQuery('')
    api.getFileContent(runId, selected)
      .then(text => {
        setJson(null)
        if (selected.endsWith('.json')) {
          try { setJson(JSON.parse(text)); setContent(text) }
          catch { setContent(text) }
        } else {
          setContent(text)
        }
      })
      .catch(e => setContent(`(load failed: ${e.message})`))
      .finally(() => setLoading(false))
  }, [selected, runId])

  async function registerTarget(domain) {
    if (!window.confirm(`Register ${domain} as a Target?\nmode: bounty · scope: ${domain} + *.${domain}`)) return
    try {
      await api.createTarget({ name: domain, mode: 'bounty', scope: [domain, `*.${domain}`], notes: 'from ST intel pivot' })
      setMsg(`✓ registered ${domain}`)
    } catch (e) {
      setMsg(`✗ ${e.message}`)
    }
    setTimeout(() => setMsg(''), 4000)
  }

  if (!checked) return <div className="p-6 text-xs" style={{ color: 'var(--text-3)' }}>Loading…</div>

  if (files.length === 0) {
    return (
      <div className="p-10 text-center">
        <p className="text-2xl mb-2" style={{ color: 'var(--text-3)' }}>⊘</p>
        <p className="text-sm mb-1" style={{ color: 'var(--text-2)' }}>No SecurityTrails intel for this run.</p>
        <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
          Set SECURITYTRAILS_KEY in /opt/k1nzr3c0n/.env and run the 01 pipeline
          (step p_securitytrails fetches everything with --mode all).
        </p>
      </div>
    )
  }

  const sel = files.find(f => f.path === selected)
  const meta = sel ? FILE_META[sel.name] : null
  const lines = content && !json ? content.split('\n').filter(Boolean) : []
  const filteredLines = query
    ? lines.filter(l => l.toLowerCase().includes(query.toLowerCase()))
    : lines
  const shown = filteredLines.slice(0, LIST_CAP)

  return (
    <div>
      {/* Summary strip */}
      <div className="flex gap-2 flex-wrap px-4 py-2.5 border-b" style={{ borderColor: 'var(--border)', background: 'var(--bg-soft)' }}>
        {files.map(f => {
          const m = FILE_META[f.name]
          const hasData = f.size > 3
          return (
            <button key={f.path} onClick={() => setSelected(f.path)}
              className="inline-flex items-center gap-1.5 text-[10px] font-mono px-2 py-1 rounded-full border transition-colors"
              style={{
                color: hasData ? 'var(--green)' : 'var(--text-3)',
                borderColor: selected === f.path ? 'var(--accent)' : 'var(--border)',
                background: selected === f.path ? 'rgba(88,166,255,.08)' : 'transparent',
              }}>
              <span className="w-1.5 h-1.5 rounded-full" style={{ background: hasData ? 'var(--green)' : 'var(--text-3)' }} />
              {m ? m.label : f.name}
              <span style={{ color: 'var(--text-3)' }}>{(f.size / 1024).toFixed(1)}K</span>
            </button>
          )
        })}
        {msg && <span className="text-[10px] font-mono self-center" style={{ color: 'var(--accent)' }}>{msg}</span>}
      </div>

      <div className="flex" style={{ minHeight: 420 }}>
        {/* File list */}
        <div className="w-52 flex-shrink-0 border-r py-2" style={{ borderColor: 'var(--border)' }}>
          {files.map(f => {
            const m = FILE_META[f.name]
            const active = f.path === selected
            const hasData = f.size > 3
            return (
              <button key={f.path} onClick={() => setSelected(f.path)}
                className="w-full text-left px-3 py-2.5 transition-colors"
                style={{
                  background: active ? 'rgba(88,166,255,.10)' : 'transparent',
                  borderLeft: active ? '2px solid var(--accent)' : '2px solid transparent',
                }}>
                <p className="text-[11px] font-semibold flex items-center gap-2"
                   style={{ color: active ? 'var(--accent)' : hasData ? 'var(--text)' : 'var(--text-3)' }}>
                  <span style={{ color: hasData ? 'var(--accent)' : 'var(--text-3)' }}>{m ? m.icon : '·'}</span>
                  {m ? m.label : f.name}
                </p>
                <p className="text-[9px] font-mono mt-0.5" style={{ color: hasData ? 'var(--text-3)' : 'var(--red)' }}>
                  {hasData ? `${f.size} bytes` : 'empty — will top-up on next run'}
                </p>
              </button>
            )
          })}
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          {meta && (
            <div className="px-4 py-2 border-b flex items-center gap-2 flex-wrap" style={{ borderColor: 'var(--border)' }}>
              <span className="text-[11px] font-bold" style={{ color: 'var(--text)' }}>{meta.icon} {meta.label}</span>
              <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{meta.hint}</span>
              <div className="flex-1" />
              {meta.kind === 'list' && lines.length > 0 && (
                <input className="input w-44" style={{ padding: '3px 8px', fontSize: 10 }}
                       placeholder={`search ${lines.length} lines…`}
                       value={query} onChange={e => setQuery(e.target.value)} />
              )}
              <span className="text-[10px] font-mono" style={{ color: 'var(--text-3)' }}>{sel.name}</span>
            </div>
          )}

          {loading ? (
            <p className="p-6 text-xs" style={{ color: 'var(--text-3)' }}>Loading…</p>
          ) : json !== null ? (
            <JsonView data={json} />
          ) : lines.length === 0 ? (
            <div className="p-10 text-center">
              <p className="text-xl mb-2" style={{ color: 'var(--text-3)' }}>∅</p>
              <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
                empty — this section hit a network dead window; the workflow's
                st_intel_retry tops it up on the next run (or run --mode missing manually).
              </p>
            </div>
          ) : (
            <div className="p-3">
              {filteredLines.length === 0 && (
                <p className="text-[11px] p-3" style={{ color: 'var(--text-3)' }}>no match for “{query}”</p>
              )}
              {shown.map((l, i) => (
                <div key={i} className="flex items-center gap-2 px-2 py-[3px] rounded hover:bg-[var(--surface-2)] group">
                  <span className="text-[10px] font-mono flex-1 truncate" style={{ color: 'var(--text-2)' }}>{l}</span>
                  {meta?.registrable && (
                    <button className="text-[9px] font-bold px-1.5 py-0.5 rounded border opacity-0 group-hover:opacity-100 transition-opacity"
                            style={{ color: 'var(--accent)', borderColor: 'rgba(88,166,255,.4)' }}
                            onClick={() => registerTarget(l.trim())}>
                      + Target
                    </button>
                  )}
                </div>
              ))}
              {filteredLines.length > LIST_CAP && (
                <p className="text-[10px] p-2 text-center" style={{ color: 'var(--text-3)' }}>
                  showing {LIST_CAP} of {filteredLines.length} — refine with search
                </p>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
