import React, { useEffect, useState } from 'react'
import { api } from '../api.js'

const STATUS_COLOR = {
  200: '#3fb950',
  301: 'var(--text-2)',
  302: 'var(--text-2)',
  401: '#d29922',
  403: '#d29922',
  500: '#f85149',
}

function statusColor(code) {
  return STATUS_COLOR[code] || (code >= 200 && code < 300 ? '#3fb950' : code >= 400 ? '#f85149' : 'var(--text-2)')
}

export default function ScreenshotGallery({ runId, steps = [] }) {
  const [shots, setShots] = useState([])
  const [loading, setLoading] = useState(true)
  const [lightbox, setLightbox] = useState(null) // { file, url, title }
  const [filter, setFilter] = useState('')

  useEffect(() => {
    api.getScreenshots(runId)
      .then(setShots)
      .catch(() => setShots([]))
      .finally(() => setLoading(false))
  }, [runId])

  function imgUrl(file) {
    return `/api/v1/runs/${runId}/files/${file}`
  }

  const filtered = filter
    ? shots.filter(s =>
        (s.url || s.name).toLowerCase().includes(filter.toLowerCase()) ||
        (s.title || '').toLowerCase().includes(filter.toLowerCase())
      )
    : shots

  if (loading) {
    return (
      <div className="flex items-center justify-center h-48 text-[var(--text-2)] text-sm">
        Loading screenshots…
      </div>
    )
  }

  if (!shots.length) {
    const screenshotStep = steps.find(s => s.id === 'screenshot')
    const stepRan = screenshotStep?.status === 'ok' || screenshotStep?.status === 'failed'
    return (
      <div className="flex flex-col items-center justify-center h-48 gap-2">
        <span className="text-4xl opacity-10">📷</span>
        <p className="text-[var(--text-2)] text-sm">No screenshots captured</p>
        <p className="text-[var(--text-3)] text-xs">
          {stepRan
            ? 'Screenshot step ran but captured nothing — target may be unreachable or Chromium timed out'
            : 'Enable run_screenshot=true and ensure gowitness + Chromium are available'}
        </p>
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Toolbar */}
      <div className="flex items-center gap-3 px-6 py-3 border-b border-[var(--surface-2)] flex-shrink-0">
        <span className="text-[var(--text-2)] text-xs tabular-nums">{filtered.length} / {shots.length} screenshots</span>
        <input
          className="ml-auto w-64 bg-[var(--bg-soft)] border border-[var(--border)] rounded px-3 py-1 text-xs text-[var(--text)] placeholder-[var(--text-3)] focus:outline-none focus:border-[#388bfd]"
          placeholder="Filter by URL or title…"
          value={filter}
          onChange={e => setFilter(e.target.value)}
        />
      </div>

      {/* Grid */}
      <div className="flex-1 overflow-y-auto p-6">
        <div className="grid gap-3" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))' }}>
          {filtered.map(s => (
            <div
              key={s.file}
              className="group rounded-lg border border-[var(--surface-2)] overflow-hidden bg-[var(--surface)] hover:border-[#388bfd] transition-colors cursor-pointer"
              onClick={() => setLightbox(s)}
            >
              {/* Thumbnail */}
              <div className="relative overflow-hidden bg-[var(--bg-soft)]" style={{ height: 160 }}>
                <img
                  src={imgUrl(s.file)}
                  alt={s.url || s.name}
                  className="w-full h-full object-cover object-top transition-transform duration-300 group-hover:scale-105"
                  loading="lazy"
                  onError={e => { e.target.style.display = 'none' }}
                />
                {/* Status badge */}
                {s.status != null && (
                  <span
                    className="absolute top-2 right-2 text-[10px] font-mono font-bold px-1.5 py-0.5 rounded"
                    style={{
                      color: statusColor(s.status),
                      background: `${statusColor(s.status)}22`,
                      border: `1px solid ${statusColor(s.status)}44`,
                    }}
                  >
                    {s.status}
                  </span>
                )}
              </div>

              {/* Meta */}
              <div className="px-3 py-2 space-y-0.5">
                {s.title && (
                  <p className="text-[11px] text-[var(--text)] font-medium truncate">{s.title}</p>
                )}
                <p className="text-[10px] text-[var(--text-2)] truncate font-mono">
                  {s.url || s.name}
                </p>
                <p className="text-[9px] text-[var(--text-3)]">
                  {(s.size / 1024).toFixed(0)} KB
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Lightbox */}
      {lightbox && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4"
          onClick={() => setLightbox(null)}
        >
          <div
            className="relative max-w-5xl w-full max-h-full overflow-auto rounded-xl border border-[var(--border)] bg-[var(--surface)] shadow-2xl"
            onClick={e => e.stopPropagation()}
          >
            {/* Lightbox header */}
            <div className="flex items-center gap-3 px-4 py-3 border-b border-[var(--surface-2)]">
              {lightbox.status != null && (
                <span
                  className="text-xs font-mono font-bold px-2 py-0.5 rounded flex-shrink-0"
                  style={{
                    color: statusColor(lightbox.status),
                    background: `${statusColor(lightbox.status)}22`,
                    border: `1px solid ${statusColor(lightbox.status)}44`,
                  }}
                >
                  {lightbox.status}
                </span>
              )}
              <div className="flex-1 min-w-0">
                {lightbox.title && (
                  <p className="text-sm text-[var(--text)] font-medium truncate">{lightbox.title}</p>
                )}
                <p className="text-xs text-[var(--text-2)] font-mono truncate">{lightbox.url || lightbox.name}</p>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                <a
                  href={imgUrl(lightbox.file)}
                  target="_blank"
                  rel="noreferrer"
                  className="px-2 py-1 text-xs rounded border border-[var(--border)] text-[var(--text-2)] hover:text-[var(--text)] hover:border-[#6e7681] transition-colors"
                  onClick={e => e.stopPropagation()}
                >
                  ↗ Full size
                </a>
                {lightbox.url && (
                  <a
                    href={lightbox.url}
                    target="_blank"
                    rel="noreferrer"
                    className="px-2 py-1 text-xs rounded border border-[var(--border)] text-[var(--text-2)] hover:text-[var(--accent)] hover:border-[#388bfd] transition-colors"
                    onClick={e => e.stopPropagation()}
                  >
                    ↗ Open URL
                  </a>
                )}
                <button
                  className="w-7 h-7 flex items-center justify-center text-[var(--text-2)] hover:text-[var(--text)] transition-colors"
                  onClick={() => setLightbox(null)}
                >
                  ✕
                </button>
              </div>
            </div>
            <img
              src={imgUrl(lightbox.file)}
              alt={lightbox.url || lightbox.name}
              className="w-full block"
            />
          </div>
        </div>
      )}
    </div>
  )
}
