import React, { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../api.js'
import { formatDuration, timeAgo, durSecs } from '../utils.js'
import NewRunModal from '../components/NewRunModal.jsx'

const SEV_META = [
  { key: 'critical', label: 'Critical', color: '#f85149' },
  { key: 'high',     label: 'High',     color: '#f0883e' },
  { key: 'medium',   label: 'Medium',   color: '#f0b429' },
  { key: 'low',      label: 'Low',      color: '#58a6ff' },
  { key: 'info',     label: 'Info',     color: '#8b949e' },
]
const UNKNOWN_COLOR = '#6e7681'

/* Small stroke icons for stat cards */
const ICONS = {
  total:     <><rect x="2" y="2" width="12" height="12" rx="2" /><path d="M2 6h12M6 6v8" /></>,
  running:   <><circle cx="8" cy="8" r="6" /><path d="M8 4.5V8l2.3 1.5" /></>,
  queued:    <><path d="M2 4h12M2 8h12M2 12h7" /></>,
  completed: <><circle cx="8" cy="8" r="6" /><path d="M5.5 8.2 7.3 10l3.2-3.8" /></>,
  failed:    <><circle cx="8" cy="8" r="6" /><path d="M6 6l4 4M10 6l-4 4" /></>,
}
function StatIcon({ d }) {
  return (
    <svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor"
         strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {d}
    </svg>
  )
}

function StatCard({ label, value, color, icon, sub, to }) {
  const navigate = useNavigate()
  return (
    <div
      className={`card card-hover p-4 fade-in ${to ? 'cursor-pointer' : ''}`}
      onClick={to ? () => navigate(to) : undefined}
      role={to ? 'link' : undefined}
    >
      <div className="flex items-start justify-between">
        <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-2)' }}>
          {label}
        </p>
        <span className="p-1.5 rounded-md" style={{ background: 'var(--surface-3)', color: color || 'var(--text-2)' }}>
          <StatIcon d={icon} />
        </span>
      </div>
      <p className="text-[28px] leading-none font-bold font-mono mt-2" style={{ color: color || 'var(--text)' }}>
        {value ?? '—'}
      </p>
      {sub && <p className="text-[10px] mt-1.5" style={{ color: 'var(--text-3)' }}>{sub}</p>}
    </div>
  )
}

function Skeleton() {
  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <div className="h-5 w-32 rounded animate-pulse" style={{ background: 'var(--surface-2)' }} />
          <div className="h-3 w-52 rounded mt-2 animate-pulse" style={{ background: 'var(--surface-2)' }} />
        </div>
        <div className="h-8 w-24 rounded-md animate-pulse" style={{ background: 'var(--surface-2)' }} />
      </div>
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="card p-4 h-[92px] animate-pulse" style={{ opacity: 1 - i * 0.12 }} />
        ))}
      </div>
      <div className="card h-64 animate-pulse" />
    </div>
  )
}

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [assets, setAssets] = useState(null)
  const [targetsTotal, setTargetsTotal] = useState(null)
  const [showModal, setShowModal] = useState(false)

  useEffect(() => {
    const load = () => api.getStats().then(setStats).catch(() => {})
    load()
    api.getAssetsStats().then(setAssets).catch(() => {})
    api.getTargets().then(t => setTargetsTotal(t?.total ?? 0)).catch(() => {})
    const t = setInterval(load, 5000)
    return () => clearInterval(t)
  }, [])

  if (!stats) return <Skeleton />

  const { total, by_status, findings, recent } = stats
  const bySev = findings?.by_severity || {}
  const unknownN = bySev.unknown || 0
  const sevTotal = SEV_META.reduce((n, s) => n + (bySev[s.key] || 0), 0) + unknownN
  const hasFindings = (findings?.total || 0) > 0
  const topTech = assets ? Object.entries(assets.by_tech || {}).slice(0, 8) : []

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Dashboard</h1>
          <p className="page-sub">Attack surface reconnaissance — run status and finding overview</p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowModal(true)}>
          <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"><path d="M8 3v10M3 8h10" /></svg>
          New Run
        </button>
      </div>

      {/* Run status cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <StatCard label="Total Runs" value={total}               icon={ICONS.total}     to="/runs" />
        <StatCard label="Running"    value={by_status.running}   icon={ICONS.running}   color="var(--green)" to="/runs?status=running" />
        <StatCard label="Queued"     value={by_status.queued}    icon={ICONS.queued}    to="/runs?status=queued" />
        <StatCard label="Completed"  value={by_status.completed} icon={ICONS.completed} color="var(--green)" to="/runs?status=completed" />
        <StatCard label="Failed"     value={by_status.failed}    icon={ICONS.failed}    color="var(--red)"   to="/runs?status=failed" />
      </div>

      {/* Attack surface overview */}
      {assets && (
        <div className="card overflow-hidden fade-in">
          <div className="card-header">
            <div className="flex items-center gap-2.5">
              <h2 className="section-title">Attack Surface</h2>
              <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                {targetsTotal ?? 0} target{(targetsTotal ?? 0) === 1 ? '' : 's'} tracked
              </span>
            </div>
            <Link to="/inventory" className="text-[10px] hover:underline" style={{ color: 'var(--accent)' }}>
              Inventory →
            </Link>
          </div>
          <div className="p-4">
            <div className="grid grid-cols-3 gap-3">
              <Link to="/inventory" className="rounded-lg p-3.5 border transition-all hover:-translate-y-px"
                    style={{ borderColor: 'var(--border)', background: 'var(--bg-soft)' }}>
                <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-2)' }}>Live hosts</p>
                <p className="text-[24px] leading-none font-bold font-mono mt-2" style={{ color: 'var(--accent)' }}>
                  {assets.total ?? 0}
                </p>
              </Link>
              <Link to="/inventory" className="rounded-lg p-3.5 border transition-all hover:-translate-y-px"
                    style={{ borderColor: 'var(--border)', background: 'var(--bg-soft)' }}>
                <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-2)' }}>Screenshots</p>
                <p className="text-[24px] leading-none font-bold font-mono mt-2" style={{ color: 'var(--text)' }}>
                  {assets.with_screenshot ?? 0}
                </p>
              </Link>
              <Link to="/findings" className="rounded-lg p-3.5 border transition-all hover:-translate-y-px"
                    style={{ borderColor: 'var(--border)', background: 'var(--bg-soft)' }}>
                <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-2)' }}>Open vulns</p>
                <p className="text-[24px] leading-none font-bold font-mono mt-2"
                   style={{ color: (findings?.open_vulns || 0) > 0 ? 'var(--red)' : 'var(--text-3)' }}>
                  {findings?.open_vulns ?? 0}
                </p>
              </Link>
            </div>
            {topTech.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-3">
                {topTech.map(([t, n]) => (
                  <span key={t} className="text-[10px] font-mono px-2 py-1 rounded-full border"
                        style={{ borderColor: 'var(--border)', color: 'var(--text-2)', background: 'var(--surface-2)' }}>
                    {t} <span style={{ color: 'var(--text-3)' }}>×{n}</span>
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Findings severity breakdown */}
      {hasFindings && (
        <div className="card overflow-hidden fade-in">
          <div className="card-header">
            <div className="flex items-center gap-2.5">
              <h2 className="section-title">Findings</h2>
              <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                {findings.total} total · {findings.open_vulns} open vulns
                {unknownN > 0 && <> · {unknownN} unclassified</>}
              </span>
            </div>
            <Link to="/findings" className="text-[10px] hover:underline" style={{ color: 'var(--accent)' }}>
              View all →
            </Link>
          </div>
          <div className="p-4">
            {/* Stacked severity distribution — part-to-whole at a glance */}
            {sevTotal > 0 && (
              <div className="flex h-2 rounded-full overflow-hidden mb-4" style={{ background: 'var(--surface-2)' }}>
                {SEV_META.map(({ key, color }) => {
                  const n = bySev[key] || 0
                  if (!n) return null
                  return (
                    <div key={key} title={`${key}: ${n}`} style={{ width: `${(n / sevTotal) * 100}%`, background: color }} />
                  )
                })}
                {unknownN > 0 && (
                  <div title={`unknown: ${unknownN}`} style={{ width: `${(unknownN / sevTotal) * 100}%`, background: UNKNOWN_COLOR }} />
                )}
              </div>
            )}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
              {SEV_META.map(({ key, label, color }) => {
                const n = bySev[key] ?? 0
                return (
                  <Link
                    key={key}
                    to={`/findings?severity=${key}`}
                    className="rounded-lg p-3.5 border transition-all hover:-translate-y-px"
                    style={{
                      borderColor: n ? color + '55' : 'var(--border)',
                      background: n ? color + '0d' : 'var(--bg-soft)',
                    }}
                  >
                    <div className="flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full" style={{ background: n ? color : 'var(--text-3)' }} />
                      <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: n ? color : 'var(--text-3)' }}>
                        {label}
                      </p>
                    </div>
                    <p className="text-[24px] leading-none font-bold font-mono mt-2" style={{ color: n ? color : 'var(--text-3)' }}>
                      {n}
                    </p>
                  </Link>
                )
              })}
            </div>
          </div>
        </div>
      )}

      {/* Recent runs */}
      <div className="card overflow-hidden fade-in">
        <div className="card-header">
          <h2 className="section-title">Recent Runs</h2>
          <Link to="/runs" className="text-[10px] hover:underline" style={{ color: 'var(--accent)' }}>
            View all →
          </Link>
        </div>
        {recent.length === 0 ? (
          <div className="p-10 text-center">
            <p className="text-sm mb-4" style={{ color: 'var(--text-2)' }}>No runs yet.</p>
            <button className="btn btn-primary" onClick={() => setShowModal(true)}>Start your first scan</button>
          </div>
        ) : (
          <table className="table-base">
            <thead>
              <tr>
                {['Target', 'Status', 'Duration', 'Started'].map(h => <th key={h}>{h}</th>)}
              </tr>
            </thead>
            <tbody>
              {recent.map(r => (
                <tr key={r.id}>
                  <td className="px-4 py-2.5">
                    <Link to={`/runs/${r.id}`} className="font-mono hover:underline" style={{ color: 'var(--accent)' }}>
                      {r.target}
                    </Link>
                    <span className="ml-2 text-[10px]" style={{ color: 'var(--text-3)' }}>{r.workflow}</span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={`badge badge-${r.status}`}>{r.status}</span>
                  </td>
                  <td className="px-4 py-2.5 font-mono" style={{ color: 'var(--text-2)' }}>
                    {r.status === 'running'
                      ? <span className="animate-pulse" style={{ color: 'var(--green)' }}>running…</span>
                      : formatDuration(durSecs(r))}
                  </td>
                  <td className="px-4 py-2.5" style={{ color: 'var(--text-2)' }} title={r.created_at}>
                    {timeAgo(r.created_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {showModal && <NewRunModal onClose={() => setShowModal(false)} onCreated={() => setShowModal(false)} />}
    </div>
  )
}
