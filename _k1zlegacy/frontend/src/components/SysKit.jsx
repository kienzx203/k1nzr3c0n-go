import React from 'react'

/* Shared scaffolding for System pages — page header + card + table. */
export function PageHeader({ icon, title, sub, right }) {
  return (
    <div className="flex items-center gap-2.5 mb-4 flex-wrap">
      <span className="p-2 rounded-lg" style={{ background: 'var(--surface-3)', color: icon.color || 'var(--accent)' }}>
        <svg width={17} height={17} viewBox="0 0 16 16" fill="none" stroke="currentColor"
             strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">{icon.d}</svg>
      </span>
      <div>
        <h2 className="text-[15px] font-bold leading-tight">{title}</h2>
        {sub && <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{sub}</p>}
      </div>
      {right && <div className="ml-auto flex gap-2">{right}</div>}
    </div>
  )
}

export function Card({ children, pad = true }) {
  return <div className={`card ${pad ? 'p-4' : ''} fade-in`}>{children}</div>
}

export function Table({ head, rows, empty = 'Nothing yet' }) {
  return (
    <div className="card overflow-auto" style={{ padding: 0, maxHeight: '66vh' }}>
      <table className="w-full text-[11.5px]" style={{ borderCollapse: 'collapse' }}>
        <thead>
          <tr className="text-left text-[9.5px] uppercase tracking-wider sticky top-0"
              style={{ color: 'var(--text-3)', background: 'var(--surface)' }}>
            {head.map(h => <th key={h} className="px-3 py-2.5 font-semibold" style={{ borderBottom: '1px solid var(--border)' }}>{h}</th>)}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className="hover:bg-[var(--surface-2)]" style={{ borderBottom: '1px solid var(--border)' }}>
              {r.map((c, j) => <td key={j} className="px-3 py-2 align-top">{c}</td>)}
            </tr>
          ))}
          {!rows.length && (
            <tr><td colSpan={head.length} className="px-3 py-10 text-center" style={{ color: 'var(--text-3)' }}>{empty}</td></tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

export function Field({ label, children }) {
  return (
    <div>
      <label className="label">{label}</label>
      {children}
    </div>
  )
}

export function Badge({ tone, children }) {
  const tones = {
    green: 'rgba(63,185,80,.14)|var(--green)', red: 'rgba(248,81,73,.14)|var(--red)',
    amber: 'rgba(240,180,41,.14)|var(--amber)', blue: 'rgba(88,166,255,.14)|var(--accent)',
    gray: 'rgba(154,167,184,.12)|var(--text-2)',
  }
  const [bg, fg] = (tones[tone] || tones.gray).split('|')
  return <span className="badge text-[9.5px] font-mono" style={{ background: bg, color: fg }}>{children}</span>
}
