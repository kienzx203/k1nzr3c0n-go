import React, { useEffect, useRef, useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { api, wsUrl } from '../api.js'
import { formatDuration, durSecs, fmtDate } from '../utils.js'
import LogViewer from '../components/LogViewer.jsx'
import FileExplorer from '../components/FileExplorer.jsx'
import StepProgress from '../components/StepProgress.jsx'
import FindingsPanel from '../components/FindingsPanel.jsx'
import ScreenshotGallery from '../components/ScreenshotGallery.jsx'
import STIntelPanel from '../components/STIntelPanel.jsx'

const TABS = ['Logs', 'Findings', 'Screenshots', 'ST Intel', 'Files', 'Report']

export default function RunDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [run, setRun] = useState(null)
  const [tab, setTab] = useState('Logs')
  const [logs, setLogs] = useState([])
  const [totalLogs, setTotalLogs] = useState(0)
  const [steps, setSteps] = useState([])
  const [screenshotCount, setScreenshotCount] = useState(null)
  const [newAssets, setNewAssets] = useState(null)
  const [pausing, setPausing] = useState(false)
  const [resuming, setResuming] = useState(false)
  const wsRef = useRef(null)
  // Latest run.status readable inside the WS effect without re-running it
  // (the old [run?.status] dep reopened the socket on every status event).
  const statusRef = useRef(null)
  useEffect(() => { statusRef.current = run?.status }, [run?.status])

  // Fetch initial log history via HTTP — works for both running and completed runs.
  // WS is live-only (no history), so this is the only source for previously written lines.
  // Prepend history instead of replacing so any live WS lines received during the fetch
  // are preserved after history loads.
  useEffect(() => {
    api.getRun(id).then(r => {
      setRun(r)
      setSteps(r.steps || [])
      const total = r.total_logs || 0
      setTotalLogs(total)
      const offset = Math.max(0, total - 500)
      return api.getLogs(id, { offset, limit: 500 }).then(res => {
        const items = res.items || []
        setLogs(prev => prev.length > 0 ? [...items, ...prev] : items)
        setTotalLogs(prev => Math.max(prev, res.total))
      })
    }).catch(() => navigate('/runs'))
  }, [id])

  // Load screenshot count for tab badge once run is known
  useEffect(() => {
    if (!run) return
    api.getScreenshots(id)
      .then(shots => setScreenshotCount(shots.length))
      .catch(() => setScreenshotCount(0))
  }, [run?.status, id])

  // New assets (first-seen hosts vs earlier runs of the same target)
  useEffect(() => {
    if (!run || !['completed', 'failed', 'paused'].includes(run.status)) return
    api.getNewAssets(id).then(r => setNewAssets(r.items || [])).catch(() => {})
  }, [run?.status, id])

  useEffect(() => {
    const TERMINAL = ['completed', 'failed', 'cancelled', 'paused', 'not_found']
    // Cap the in-memory live buffer — scans can emit 100k+ lines and the old
    // unbounded [...prev, line] copy pegged a CPU core. Older lines stay
    // reachable via LogViewer's "load older" (totalLogs + HTTP fetch).
    const MAX_LIVE_LOGS = 5000
    let disposed = false
    let ws = null
    let reconnectTimer = null
    let attempts = 0

    function connect() {
      if (disposed || TERMINAL.includes(statusRef.current)) return
      ws = new WebSocket(wsUrl(id))
      wsRef.current = ws

      ws.onopen = () => { attempts = 0 }

      ws.onmessage = (e) => {
        let data
        try { data = JSON.parse(e.data) } catch { return }
        if (data.type === 'log_meta') {
          // Server tells us the current total in DB — used by LogViewer "load older"
          setTotalLogs(prev => Math.max(prev, data.total))
        }
        if (data.type === 'log') {
          // Append only NEW live lines; history already loaded via HTTP above
          setLogs(prev => {
            const next = prev.length >= MAX_LIVE_LOGS ? prev.slice(prev.length - MAX_LIVE_LOGS + 1) : prev.slice()
            next.push(data.message)
            return next
          })
          setTotalLogs(prev => prev + 1)
        }
        if (data.type === 'step') {
          setSteps(data.steps)
        }
        if (data.type === 'status') {
          statusRef.current = data.status
          setRun(prev => prev ? { ...prev, status: data.status } : prev)
        }
        if (data.type === 'done') {
          statusRef.current = data.status
          setPausing(false)
          setResuming(false)
          setRun(prev => prev ? {
            ...prev,
            status: data.status,
            finished_at: prev.finished_at || new Date().toISOString(),
          } : prev)
          if (data.steps) setSteps(data.steps)
          try { ws.close() } catch { /* already closed */ }
          // Re-fetch full run to pick up server-side finished_at and findings_count
          api.getRun(id).then(r => { setRun(r); setSteps(r.steps || []) }).catch(() => {})
        }
      }

      ws.onclose = () => {
        if (disposed || TERMINAL.includes(statusRef.current)) return
        // Reconnect with capped backoff — server restart or a dropped
        // connection used to freeze the UI on "running" forever.
        const delay = Math.min(1000 * 2 ** attempts, 15000)
        attempts += 1
        reconnectTimer = setTimeout(connect, delay)
      }
      ws.onerror = () => { try { ws.close() } catch { /* noop */ } }
    }

    connect()

    // Fallback poll: guarantees the UI converges to the real status even if
    // the WS misses the one-shot "done" event — and re-attaches the live
    // stream when a paused/failed run is resumed.
    const poll = setInterval(() => {
      api.getRun(id).then(r => {
        const wasTerminal = TERMINAL.includes(statusRef.current)
        const isTerminal = TERMINAL.includes(r.status)
        if (isTerminal && !wasTerminal) {
          statusRef.current = r.status
          setRun(r); setSteps(r.steps || [])
          setPausing(false); setResuming(false)
          try { ws?.close() } catch { /* noop */ }
        } else if (!isTerminal && wasTerminal) {
          statusRef.current = r.status
          setRun(r); setSteps(r.steps || [])
          connect()
        }
      }).catch(() => {})
    }, 5000)

    return () => {
      disposed = true
      clearInterval(poll)
      if (reconnectTimer) clearTimeout(reconnectTimer)
      try { ws?.close() } catch { /* noop */ }
    }
  }, [id])

  if (!run) return <div className="p-8 text-[var(--text-2)] text-sm">Loading…</div>

  const dur = run.status === 'running' ? 'running…' : formatDuration(durSecs(run))

  const isDone = ['completed', 'failed', 'cancelled', 'paused'].includes(run.status)
  const isActive = run.status === 'running'
  const isPaused = run.status === 'paused'
  const canResume = ['paused', 'failed'].includes(run.status)

  async function handlePause() {
    setPausing(true)
    try {
      await api.pauseRun(id)
      // Don't touch run.status — the WebSocket `done` event will set it to "paused"
    } catch (e) {
      setPausing(false)
    }
  }

  async function handleCancelPause() {
    try {
      await api.cancelPause(id)
      setPausing(false)
    } catch (e) {
      // If it 400s (run already paused), reset state and let WS done event take over
      setPausing(false)
    }
  }

  async function handleResume() {
    setResuming(true)
    try {
      const r = await api.resumeRun(id)
      setRun(r)
      setSteps(r.steps || [])
      // Run is now 'running' — resuming state no longer needed (WS done event will also clear it)
      setResuming(false)
    } catch (e) {
      setResuming(false)
    }
  }

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="border-b border-[var(--border)] px-6 py-4 flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Link to="/runs" className="text-[var(--text-2)] hover:text-[var(--accent)] text-xs">Runs</Link>
            <span className="text-[var(--border)]">/</span>
            <span className="text-xs text-[var(--text)] font-mono">{id}</span>
          </div>
          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="text-base font-bold text-[var(--text)] font-mono">{run.target}</h1>
            <span className={`badge badge-${run.status}`}>{run.status}</span>
            <span className="text-[var(--text-2)] text-xs">{run.workflow}</span>
            {run.findings_count > 0 && (
              <span className="text-xs font-mono border border-[var(--orange)] text-[var(--orange)] rounded px-1.5 py-0.5">
                {run.findings_count} findings
              </span>
            )}
          </div>
          <div className="flex gap-4 mt-1 text-[11px] text-[var(--text-2)] flex-wrap">
            <span title={run.started_at || run.created_at}>
              Started: {fmtDate(run.started_at || run.created_at)}
            </span>
            <span>Duration: <span className={run.status === 'running' ? 'text-[var(--green)]' : ''}>{dur}</span></span>
            {run.returncode != null && run.returncode !== 0 && (
              <span className="text-[var(--red)]">Exit: {run.returncode}</span>
            )}
            <button
              className="text-[var(--text-3)] hover:text-[var(--text-2)] font-mono transition-colors"
              title="Copy run ID"
              onClick={() => navigator.clipboard.writeText(id)}
            >{id} ⧉</button>
          </div>
        </div>
        <div className="flex gap-2 items-center flex-wrap">
          {isActive && !pausing && (
            <button
              className="btn"
              style={{ color: '#f0b429', borderColor: '#f0b42966' }}
              onClick={handlePause}
            >
              ⏸ Pause
            </button>
          )}
          {isActive && pausing && (
            <>
              <span className="text-xs text-[var(--amber)] self-center whitespace-nowrap">⌛ Pausing after current step…</span>
              <button
                className="btn btn-ghost text-xs"
                onClick={handleCancelPause}
              >
                ✕ Cancel Pause
              </button>
            </>
          )}
          {isActive && (
            <button className="btn btn-danger" onClick={() => api.cancelRun(id).then(r => setRun(r))}>
              ■ Cancel
            </button>
          )}
          {canResume && (
            <button
              className="btn"
              style={{ color: resuming ? 'var(--text-2)' : '#3fb950', borderColor: resuming ? 'var(--border)' : '#3fb95066' }}
              onClick={handleResume}
              disabled={resuming}
            >
              {resuming ? '⌛ Resuming…' : '▶ Resume'}
            </button>
          )}
          {isPaused && !resuming && (
            <span className="text-xs text-[var(--amber)] self-center">
              ⏸ Paused — progress saved
            </span>
          )}
          {isDone && (
            <>
              <a
                href={api.reportUrl(id)}
                target="_blank"
                rel="noreferrer"
                className="btn"
                style={{ fontSize: 12 }}
              >
                ↗ Report
              </a>
              <a
                href={api.reportDraftUrl(id, 'hackerone')}
                title="Submission-ready markdown drafts (HackerOne format) for every open vuln"
                className="btn btn-accent"
                style={{ fontSize: 12 }}
              >
                ⬇ Draft H1
              </a>
              <a
                href={api.reportDraftUrl(id, 'bugcrowd')}
                title="Submission-ready markdown drafts (Bugcrowd format)"
                className="btn btn-ghost"
                style={{ fontSize: 12 }}
              >
                ⬇ Draft BC
              </a>
            </>
          )}
        </div>
      </div>

      {/* New assets discovered by this run (first-seen vs earlier runs) */}
      {newAssets && newAssets.length > 0 && (
        <div className="mx-6 mt-4 px-4 py-2.5 rounded-lg fade-in"
             style={{ background: 'rgba(63,185,80,.07)', border: '1px solid rgba(63,185,80,.35)' }}>
          <p className="text-xs font-semibold mb-1.5" style={{ color: 'var(--green)' }}>
            🆕 {newAssets.length} new asset{newAssets.length > 1 ? 's' : ''} first seen in this run
          </p>
          <div className="flex gap-1.5 flex-wrap">
            {newAssets.slice(0, 12).map(a => (
              <span key={a.id} className="text-[10px] font-mono px-1.5 py-0.5 rounded"
                    style={{ background: 'var(--surface)', color: 'var(--text-2)', border: '1px solid var(--border)' }}>
                {a.host}
              </span>
            ))}
            {newAssets.length > 12 && (
              <span className="text-[10px] self-center" style={{ color: 'var(--text-3)' }}>
                +{newAssets.length - 12} more
              </span>
            )}
          </div>
        </div>
      )}

      {/* Step progress */}
      <StepProgress steps={steps} running={isActive} />

      {/* Tabs */}
      <div className="border-b border-[var(--border)] px-6 flex gap-0">
        {TABS.map(t => {
          const count = t === 'Findings' && run.findings_count > 0
            ? run.findings_count
            : t === 'Screenshots' && screenshotCount > 0
            ? screenshotCount
            : null
          return (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-4 py-2.5 text-xs border-b-2 transition-colors flex items-center gap-1.5 ${
                tab === t ? 'border-[var(--accent)] text-[var(--accent)]' : 'border-transparent text-[var(--text-2)] hover:text-[var(--text)]'
              }`}
            >
              {t}
              {count != null && (
                <span className="text-[9px] bg-[#FF8C4233] text-[var(--orange)] rounded px-1">{count}</span>
              )}
            </button>
          )
        })}
      </div>

      {/* Content — Logs/Findings/Screenshots manage their own inner scroll;
          the rest get a page-level scroll container (was overflow-hidden →
          long content unreachable). */}
      <div className="flex-1 overflow-hidden">
        {tab === 'Logs' && (
          <LogViewer logs={logs} running={isActive} runId={id} totalLogs={totalLogs} />
        )}
        {tab === 'Findings' && <FindingsPanel runId={id} />}
        {tab === 'Screenshots' && <ScreenshotGallery runId={id} steps={steps} />}
        {tab === 'ST Intel' && (
          <div className="h-full overflow-y-auto"><STIntelPanel runId={id} /></div>
        )}
        {tab === 'Files' && (
          <div className="h-full overflow-y-auto"><FileExplorer runId={id} /></div>
        )}
        {tab === 'Report' && (
          <div className="h-full overflow-y-auto"><div className="p-6 space-y-4">
            {isDone ? (
              <>
                <p className="text-sm text-[var(--text-2)]">
                  The report is generated on-the-fly from the structured findings in the database.
                  It includes vulnerabilities, HTTP services, open ports, and discovered subdomains.
                </p>
                <div className="flex gap-3">
                  <a
                    href={api.reportUrl(id)}
                    target="_blank"
                    rel="noreferrer"
                    className="btn"
                  >
                    ↗ Open HTML Report
                  </a>
                  <button
                    onClick={() => api.reparseFinding(id).then(() => setRun(r => ({ ...r })))}
                    className="btn"
                  >
                    ↺ Reparse Findings
                  </button>
                </div>
                <p className="text-xs text-[var(--text-2)]">
                  The report opens in a new tab and can be saved as PDF via browser print (Ctrl+P → Save as PDF).
                </p>
              </>
            ) : (
              <p className="text-sm text-[var(--text-2)]">Report is available after the run completes.</p>
            )}
          </div></div>
        )}
      </div>
    </div>
  )
}
