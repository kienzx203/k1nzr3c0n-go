import React, { useEffect, useState } from 'react'
import { api } from '../api.js'

/* Bottom status bar: health · capture · LLM usage — like an IDE status strip. */
export default function StatusFooter() {
  const [health, setHealth] = useState(null)
  const [capture, setCapture] = useState(null)
  const [usage, setUsage] = useState(null)
  const [upd, setUpd] = useState(null)

  useEffect(() => {
    const load = async () => {
      try { setHealth(await api.getHealth()) } catch {}
      try { setCapture(await api.captureStatus()) } catch {}
      try { setUsage(await api.llmUsage()) } catch {}
    }
    api.updateCheck().then(setUpd).catch(() => {})
    load()
    const t = setInterval(load, 15000)
    return () => clearInterval(t)
  }, [])

  const status = health?.status
  const fmt = n => n >= 1000000 ? (n / 1e6).toFixed(1) + 'M' : n >= 1000 ? (n / 1e3).toFixed(1) + 'k' : String(n ?? 0)

  return (
    <footer className="flex items-center gap-4 px-4 py-1.5 text-[10px] border-t select-none"
            style={{ borderColor: 'var(--border)', background: 'var(--bg-soft)', color: 'var(--text-3)' }}>
      <span className="flex items-center gap-1.5">
        <span style={{
          width: 7, height: 7, borderRadius: '50%', display: 'inline-block',
          background: status === 'ok' ? 'var(--green)' : status ? 'var(--amber)' : 'var(--text-3)',
          boxShadow: status === 'ok' ? '0 0 6px var(--green)' : 'none',
        }} />
        {status ? `system ${status}` : 'system …'}
      </span>
      {capture?.available && (
        <span className="flex items-center gap-1.5">
          <span style={{
            width: 7, height: 7, borderRadius: '50%', display: 'inline-block',
            background: capture.enabled ? 'var(--orange)' : 'var(--text-3)',
            boxShadow: capture.enabled ? '0 0 6px var(--orange)' : 'none',
          }} />
          capture {capture.enabled ? 'on' : 'off'}
        </span>
      )}
      {usage && usage.turns > 0 && (
        <span className="font-mono">
          llm {usage.turns} turns · {fmt(usage.total_tokens)} tok
        </span>
      )}
      {upd?.update_available && (
        <button className="font-mono hover:underline" style={{ color: 'var(--accent)' }}
                title="Download the new binary (swap) — restart the service afterward"
                onClick={async () => {
                  try { await api.selfUpdate(); alert('Binary updated — run: systemctl restart k1nzr3c0n-go') } catch (e) { alert(e.message) }
                }}>
          ↑ {upd.latest} — update available
        </button>
      )}
      <span className="ml-auto font-mono">k1nzr3c0n-go {upd?.current || ''}</span>
    </footer>
  )
}
