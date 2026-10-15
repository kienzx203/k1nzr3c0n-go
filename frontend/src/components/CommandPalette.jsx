import React, { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api.js'

const PAGES = [
  { label: 'Dashboard', to: '/',           hint: 'Overview' },
  { label: 'Runs',      to: '/runs',       hint: 'Operations' },
  { label: 'Workflows', to: '/workflows',  hint: 'Operations' },
  { label: 'Findings',  to: '/findings',   hint: 'Operations' },
  { label: 'Inventory', to: '/inventory',  hint: 'Operations' },
  { label: 'Schedules', to: '/schedules',  hint: 'Continuous recon' },
  { label: 'Targets',   to: '/targets',    hint: 'Scope & history' },
  { label: 'Upload',    to: '/upload',     hint: 'Capture' },
  { label: 'Terminal',  to: '/terminal',   hint: 'System' },
  { label: 'API Keys',  to: '/keys',       hint: 'System' },
  { label: 'Tools',     to: '/tools',      hint: 'System' },
]

export default function CommandPalette() {
  const [open, setOpen] = useState(false)
  const [q, setQ] = useState('')
  const [items, setItems] = useState([])
  const [idx, setIdx] = useState(0)
  const inputRef = useRef(null)
  const navigate = useNavigate()

  useEffect(() => {
    const onKey = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setOpen(o => !o)
      }
      if (e.key === 'Escape') setOpen(false)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  useEffect(() => {
    if (!open) return
    setQ(''); setIdx(0)
    setTimeout(() => inputRef.current?.focus(), 0)
    // Lazy-load dynamic entries (targets + recent runs) while typing pages instantly
    Promise.all([
      api.getTargets().catch(() => ({ items: [] })),
      api.getRuns({ limit: 8 }).catch(() => ({ items: [] })),
    ]).then(([targets, runs]) => {
      setItems([
        ...PAGES.map(p => ({ ...p, kind: 'page' })),
        ...(targets.items || []).map(t => ({
          label: t.name, to: `/targets?sel=${encodeURIComponent(t.name)}`,
          hint: `Target · ${t.mode || 'bounty'} · ${t.total_runs ?? 0} runs`, kind: 'target',
        })),
        ...(runs.items || []).map(r => ({
          label: r.target, to: `/runs/${r.id}`,
          hint: `Run · ${r.status} · ${r.workflow}`, kind: 'run',
        })),
      ])
    })
  }, [open])

  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase()
    if (!s) return items
    return items.filter(i => i.label.toLowerCase().includes(s) || (i.hint || '').toLowerCase().includes(s))
  }, [q, items])

  const go = (item) => {
    if (!item) return
    setOpen(false)
    navigate(item.to)
  }

  const onKey = (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setIdx(i => Math.min(i + 1, filtered.length - 1)) }
    if (e.key === 'ArrowUp')   { e.preventDefault(); setIdx(i => Math.max(i - 1, 0)) }
    if (e.key === 'Enter')     { e.preventDefault(); go(filtered[idx]) }
  }

  if (!open) return null

  const KIND_ICON = { page: '▦', target: '⌖', run: '▶' }

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[12vh] px-4"
      style={{ background: 'rgba(0,0,0,.55)', backdropFilter: 'blur(2px)' }}
      onClick={() => setOpen(false)}
    >
      <div
        className="w-full max-w-lg card overflow-hidden fade-in"
        style={{ boxShadow: 'var(--shadow-2)' }}
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center gap-2 px-3 border-b" style={{ borderColor: 'var(--border)' }}>
          <span style={{ color: 'var(--text-3)' }}>⌕</span>
          <input
            ref={inputRef}
            className="flex-1 bg-transparent py-3 text-sm outline-none"
            style={{ color: 'var(--text)' }}
            placeholder="Jump to page, target, or run…"
            value={q}
            onChange={e => { setQ(e.target.value); setIdx(0) }}
            onKeyDown={onKey}
          />
          <kbd className="text-[9px] px-1.5 py-0.5 rounded border" style={{ color: 'var(--text-3)', borderColor: 'var(--border)' }}>ESC</kbd>
        </div>
        <div className="max-h-[46vh] overflow-y-auto py-1">
          {filtered.length === 0 && (
            <p className="px-4 py-6 text-xs text-center" style={{ color: 'var(--text-3)' }}>No matches</p>
          )}
          {filtered.map((item, i) => (
            <button
              key={`${item.kind}-${item.to}-${i}`}
              className="w-full flex items-center gap-2.5 px-3 py-2 text-left text-xs transition-colors"
              style={i === idx ? { background: 'rgba(88,166,255,.12)', color: 'var(--text)' } : { color: 'var(--text-2)' }}
              onMouseEnter={() => setIdx(i)}
              onClick={() => go(item)}
            >
              <span className="w-4 text-center" style={{ color: i === idx ? 'var(--accent)' : 'var(--text-3)' }}>
                {KIND_ICON[item.kind] || '·'}
              </span>
              <span className="font-medium font-mono">{item.label}</span>
              <span className="ml-auto text-[10px] truncate max-w-[45%]" style={{ color: 'var(--text-3)' }}>{item.hint}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}
