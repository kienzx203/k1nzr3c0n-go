import React, { useEffect, useMemo, useRef, useState } from 'react'

// Two-level "Add Filters" flyout: left column picks a facet category, right
// column is a searchable checkbox multi-select for that facet's values.
// Nothing is applied until the user hits "Apply" — matches the common
// asset-inventory filter UX (pick across several categories, commit once).
//
// categories: [{ key, label, icon, options: [{ value, label, count }] }]
// applied: { [key]: string[] }
export default function AddFiltersMenu({ categories, applied, onApply }) {
  const [open, setOpen] = useState(false)
  const [activeKey, setActiveKey] = useState(categories[0]?.key)
  const [pending, setPending] = useState(applied)
  const [query, setQuery] = useState('')
  const rootRef = useRef(null)

  // Re-seed the draft from the currently-applied filters each time the menu opens
  useEffect(() => {
    if (open) { setPending(applied); setQuery('') }
  }, [open]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    function onClickOutside(e) {
      if (rootRef.current && !rootRef.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', onClickOutside)
    return () => document.removeEventListener('mousedown', onClickOutside)
  }, [])

  const active = categories.find(c => c.key === activeKey) || categories[0]
  const activeSelected = new Set(pending[activeKey] || [])

  const filteredOptions = useMemo(() => {
    if (!active) return []
    if (!query) return active.options
    const ql = query.toLowerCase()
    return active.options.filter(o => o.label.toLowerCase().includes(ql))
  }, [active, query])

  const pendingCount = Object.values(pending).reduce((n, arr) => n + (arr?.length || 0), 0)
  const appliedCount = Object.values(applied).reduce((n, arr) => n + (arr?.length || 0), 0)

  function toggle(value) {
    setPending(prev => {
      const cur = new Set(prev[activeKey] || [])
      cur.has(value) ? cur.delete(value) : cur.add(value)
      return { ...prev, [activeKey]: [...cur] }
    })
  }

  function clearAll() {
    const empty = Object.fromEntries(categories.map(c => [c.key, []]))
    setPending(empty)
  }

  function apply() {
    onApply(pending)
    setOpen(false)
  }

  return (
    <div ref={rootRef} className="relative">
      <button
        onClick={() => setOpen(o => !o)}
        className={`btn flex items-center gap-2 ${appliedCount > 0 ? 'border-[#58a6ff66] text-[var(--accent)]' : 'btn-ghost'}`}
        style={{ borderWidth: 1, borderStyle: 'solid', borderColor: appliedCount > 0 ? undefined : 'var(--border)' }}
      >
        <span>☰</span> Add Filters
        {appliedCount > 0 && (
          <span className="text-[11px] px-1.5 rounded-full bg-[#58a6ff22] text-[var(--accent)]">{appliedCount}</span>
        )}
      </button>

      {open && (
        <div className="absolute z-30 mt-1 left-0 card overflow-hidden shadow-2xl flex" style={{ width: 480 }}>
          {/* Left: category list */}
          <div className="w-44 flex-shrink-0 border-r border-[var(--border)] py-1.5 max-h-96 overflow-y-auto">
            {categories.map(c => {
              const n = (pending[c.key] || []).length
              return (
                <button
                  key={c.key}
                  onMouseEnter={() => setActiveKey(c.key)}
                  onClick={() => setActiveKey(c.key)}
                  className={`w-full flex items-center justify-between gap-2 px-3 py-1.5 text-left text-xs transition-colors
                    ${activeKey === c.key ? 'bg-[var(--surface)] text-[var(--text)]' : 'text-[var(--text-2)] hover:bg-[var(--surface-2)] hover:text-[var(--text)]'}`}
                >
                  <span className="flex items-center gap-2 truncate">
                    <span className="opacity-70">{c.icon}</span> {c.label}
                    {n > 0 && <span className="text-[11px] px-1.5 rounded-full bg-[#58a6ff22] text-[var(--accent)]">{n}</span>}
                  </span>
                  <span className="text-[var(--text-3)]">›</span>
                </button>
              )
            })}
          </div>

          {/* Right: searchable checkbox list for the active category */}
          <div className="flex-1 flex flex-col min-w-0">
            <div className="p-2 border-b border-[var(--border)]">
              <div className="relative">
                <input
                  value={query}
                  onChange={e => setQuery(e.target.value)}
                  placeholder={`Search ${active?.label.toLowerCase()}…`}
                  className="input py-1 pr-7"
                />
                <span className="absolute right-2 top-1/2 -translate-y-1/2 text-[var(--text-3)]">⌕</span>
              </div>
            </div>
            <div className="flex-1 overflow-y-auto max-h-72 py-1">
              {filteredOptions.length === 0 && (
                <div className="px-3 py-3 text-[12px] text-[var(--text-3)]">No matches</div>
              )}
              {filteredOptions.map(o => (
                <label
                  key={o.value}
                  className="flex items-center justify-between gap-2 px-3 py-1.5 text-xs cursor-pointer hover:bg-[var(--surface-2)] transition-colors"
                >
                  <span className="flex items-center gap-2 min-w-0">
                    <input
                      type="checkbox"
                      checked={activeSelected.has(o.value)}
                      onChange={() => toggle(o.value)}
                      className="accent-[var(--accent)] flex-shrink-0"
                    />
                    <span className="truncate text-[var(--text)]">{o.label}</span>
                  </span>
                  {o.count != null && (
                    <span className="text-[11px] text-[var(--text-2)] border border-[var(--border)] rounded px-1.5 flex-shrink-0">{o.count}</span>
                  )}
                </label>
              ))}
            </div>
            {/* Bottom bar */}
            <div className="flex items-center gap-2 p-2 border-t border-[var(--border)]">
              <button
                onClick={clearAll}
                title="Clear all pending selections"
                className="w-7 h-7 flex items-center justify-center rounded border border-[var(--border)] text-[var(--text-2)] hover:text-[var(--red)] hover:border-[var(--red)] transition-colors"
              >
                ✕
              </button>
              <button onClick={apply} className="btn btn-primary flex-1">
                Apply {pendingCount > 0 ? `(${pendingCount})` : ''}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
