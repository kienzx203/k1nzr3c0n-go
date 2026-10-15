import React, { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../api.js'

const ROW_H = 20        // px — fixed-height rows for virtual rendering
const WIN_ROWS = 300    // how many rows to render in the DOM at once
const MAX_BUFFER = 3000 // rolling live-stream buffer

function classify(line) {
  // Workflow engine markers
  if (line.startsWith('[+]'))    return 'log-ok'
  if (line.startsWith('[!]'))    return 'log-warn'
  if (line.startsWith('[x]'))    return 'log-error'
  if (/^\[PAUSED\]/.test(line)) return 'log-warn'
  // Nuclei severity hits (e.g. "[critical]", "[high]")
  if (/\[(critical|high)\]/i.test(line))   return 'log-error'
  if (/\[medium\]/i.test(line))            return 'log-warn'
  if (/\[(low|info)\]/i.test(line) && /\[\w+\]\s+\[/.test(line)) return 'log-info'
  // Tool output tags: [INF] [WRN] [ERR] [FTL] used by PD tools
  if (/\[INF\]|\[INFO\]/.test(line))       return 'log-info'
  if (/\[WRN\]|\[WARN\]/.test(line))       return 'log-warn'
  if (/\[ERR\]|\[ERROR\]|\[FTL\]/.test(line)) return 'log-error'
  // Generic error patterns
  if (/\bfailed\b|\bfatal\b/i.test(line))  return 'log-error'
  if (/\bwarning\b/i.test(line))           return 'log-warn'
  return 'log-plain'
}

export default function LogViewer({ logs, running, runId, totalLogs = 0 }) {
  const containerRef = useRef(null)
  const bottomRef = useRef(null)
  const [autoScroll, setAutoScroll] = useState(true)
  const [filter, setFilter] = useState('')
  const [scrollTop, setScrollTop] = useState(0)
  const [extraLogs, setExtraLogs] = useState([])   // older logs loaded from API
  const [loadingOlder, setLoadingOlder] = useState(false)
  const [olderLoaded, setOlderLoaded] = useState(0) // how many older lines loaded

  // Roll buffer: keep last MAX_BUFFER live lines
  const allLogs = extraLogs.length ? [...extraLogs, ...logs] : logs
  const hiddenCount = Math.max(0, allLogs.length - MAX_BUFFER)
  const buffered = hiddenCount > 0 ? allLogs.slice(hiddenCount) : allLogs

  const visible = filter
    ? buffered.filter(l => l.toLowerCase().includes(filter.toLowerCase()))
    : buffered

  // Auto-scroll to bottom
  useEffect(() => {
    if (autoScroll && !filter) {
      bottomRef.current?.scrollIntoView({ behavior: 'instant' })
    }
  }, [logs.length, autoScroll, filter])

  // Detect manual scroll up → disable auto-scroll
  const handleScroll = useCallback((e) => {
    const el = e.target
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40
    if (!atBottom && autoScroll) setAutoScroll(false)
    if (atBottom && !autoScroll) setAutoScroll(true)
    setScrollTop(el.scrollTop)
  }, [autoScroll])

  // Virtual window: only render WIN_ROWS rows
  const totalH = visible.length * ROW_H
  const startIdx = Math.max(0, Math.floor(scrollTop / ROW_H) - 50)
  const endIdx = Math.min(visible.length, startIdx + WIN_ROWS)
  const paddingTop = startIdx * ROW_H
  const paddingBot = Math.max(0, (visible.length - endIdx) * ROW_H)

  // Load older logs from API
  const loadOlder = useCallback(async () => {
    if (!runId || loadingOlder) return
    setLoadingOlder(true)
    try {
      const alreadyHave = logs.length + extraLogs.length
      const serverTotal = totalLogs || alreadyHave
      const newOffset = Math.max(0, serverTotal - alreadyHave - 1000)
      const res = await api.getLogs(runId, { offset: newOffset, limit: 1000 })
      const fetched = res.items || []
      setExtraLogs(prev => {
        const combined = [...fetched, ...prev]
        // deduplicate by position
        return combined.slice(-5000)
      })
      setOlderLoaded(v => v + fetched.length)
    } catch (_) {
      // ignore
    } finally {
      setLoadingOlder(false)
    }
  }, [runId, loadingOlder, logs.length, extraLogs.length, totalLogs])

  const serverTotal = totalLogs || allLogs.length
  const canLoadOlder = runId && (allLogs.length < serverTotal || olderLoaded === 0)

  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div className="flex items-center gap-3 px-4 py-2 border-b border-[var(--border)] flex-shrink-0 flex-wrap">
        <input
          className="input w-56 py-1"
          placeholder="Filter…"
          value={filter}
          onChange={e => setFilter(e.target.value)}
        />
        <label className="flex items-center gap-1.5 text-xs text-[var(--text-2)] cursor-pointer select-none">
          <input type="checkbox" checked={autoScroll} onChange={e => setAutoScroll(e.target.checked)} className="accent-[var(--accent)]" />
          Auto-scroll
        </label>
        <span className="text-xs text-[var(--text-2)] ml-auto">
          {visible.length.toLocaleString()} lines
          {serverTotal > visible.length && !filter && (
            <span className="text-[var(--text-2)]"> / {serverTotal.toLocaleString()} total</span>
          )}
        </span>
        {running && <span className="text-xs text-[var(--green)] animate-pulse font-mono">● live</span>}
      </div>

      {/* Log pane */}
      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto px-4 py-3 bg-[var(--bg-soft)]"
        style={{ fontSize: 11, lineHeight: `${ROW_H}px`, fontFamily: 'monospace' }}
      >
        {/* Load-older banner */}
        {canLoadOlder && !filter && (
          <div className="flex items-center justify-center mb-3 gap-2">
            <button
              onClick={loadOlder}
              disabled={loadingOlder}
              className="text-xs text-[var(--text-2)] hover:text-[var(--text)] border border-[var(--border)] rounded px-3 py-1 transition-colors disabled:opacity-50"
            >
              {loadingOlder ? 'Loading…' : `↑ Load older lines (${(serverTotal - allLogs.length).toLocaleString()} not shown)`}
            </button>
          </div>
        )}

        {hiddenCount > 0 && !filter && (
          <div className="text-center text-[10px] text-[#536180] mb-2 font-mono">
            — {hiddenCount.toLocaleString()} older lines in memory buffer —
          </div>
        )}

        {visible.length === 0 && (
          <p className="text-[var(--text-2)]">{running ? 'Waiting for output…' : 'No logs.'}</p>
        )}

        {/* Virtual scroll spacers + windowed rows */}
        <div style={{ height: totalH, position: 'relative' }}>
          <div style={{ position: 'absolute', top: paddingTop, width: '100%' }}>
            {visible.slice(startIdx, endIdx).map((line, i) => (
              <div key={startIdx + i} className={classify(line)} style={{ height: ROW_H, overflow: 'hidden', whiteSpace: 'nowrap', textOverflow: 'ellipsis' }}>
                {line}
              </div>
            ))}
          </div>
        </div>

        <div ref={bottomRef} />
      </div>
    </div>
  )
}
