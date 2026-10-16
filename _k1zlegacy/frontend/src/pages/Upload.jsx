import React, { useState, useRef, useCallback, useEffect } from 'react'

const API = '/api/v1'

function fmt(bytes) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 ** 2).toFixed(1)} MB`
}

function fmtLines(n) {
  if (!n) return ''
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M lines`
  if (n >= 1000) return `${(n / 1000).toFixed(0)}k lines`
  return `${n} lines`
}

// ── Drag-and-drop upload zone ─────────────────────────────────────────────────
function DropZone({ accept, label, hint, onFiles, disabled }) {
  const [over, setOver] = useState(false)
  const inputRef = useRef(null)

  const handle = useCallback((files) => {
    if (disabled || !files?.length) return
    onFiles(Array.from(files))
  }, [disabled, onFiles])

  return (
    <div
      onClick={() => !disabled && inputRef.current?.click()}
      onDragOver={e => { e.preventDefault(); setOver(true) }}
      onDragLeave={() => setOver(false)}
      onDrop={e => { e.preventDefault(); setOver(false); handle(e.dataTransfer.files) }}
      className={`
        relative border-2 border-dashed rounded-lg px-6 py-10 text-center cursor-pointer transition-colors
        ${over && !disabled
          ? 'border-[var(--accent)] bg-[#58a6ff0d]'
          : disabled
            ? 'border-[var(--surface-2)] opacity-50 cursor-not-allowed'
            : 'border-[var(--border)] hover:border-[#58a6ff66] hover:bg-[var(--surface-2)]'
        }
      `}
    >
      <input
        ref={inputRef}
        type="file"
        accept={accept}
        multiple
        className="hidden"
        onChange={e => { handle(e.target.files); e.target.value = '' }}
        disabled={disabled}
      />
      <div className="text-3xl mb-2 select-none">↑</div>
      <p className="text-[var(--text)] text-sm font-medium">{label}</p>
      <p className="text-[var(--text-2)] text-xs mt-1">{hint}</p>
    </div>
  )
}

// ── Single upload row feedback ────────────────────────────────────────────────
function UploadRow({ name, status, error }) {
  return (
    <div className={`flex items-center gap-2 text-xs py-1 px-2 rounded font-mono
      ${status === 'done'    ? 'text-[#56d364]' :
        status === 'error'   ? 'text-[#ff7b72]' :
        status === 'loading' ? 'text-[var(--amber)]' : 'text-[var(--text-2)]'}`}>
      <span>{status === 'loading' ? '…' : status === 'done' ? '✓' : '✕'}</span>
      <span className="flex-1 truncate">{name}</span>
      {error && <span className="text-[10px] opacity-75">{error}</span>}
    </div>
  )
}

// ── File list item ────────────────────────────────────────────────────────────
function FileItem({ name, size, lines, path, onDelete }) {
  const [copied, setCopied] = useState(false)
  const [deleting, setDeleting] = useState(false)

  const copy = () => {
    navigator.clipboard.writeText(path)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  return (
    <div className="flex items-center gap-2 px-3 py-2 rounded hover:bg-[var(--surface-2)] group transition-colors">
      <span className="text-[#6e7681] text-xs font-mono flex-1 truncate">{name}</span>
      {lines ? <span className="text-[10px] text-[#6e7681] flex-shrink-0">{fmtLines(lines)}</span> : null}
      <span className="text-[10px] text-[#6e7681] flex-shrink-0">{fmt(size)}</span>
      {path && (
        <button
          onClick={copy}
          title="Copy path"
          className="opacity-0 group-hover:opacity-100 text-[10px] px-1.5 py-0.5 rounded bg-[var(--surface-2)] border border-[var(--border)] text-[var(--text-2)] hover:text-[var(--text)] transition-all flex-shrink-0"
        >
          {copied ? '✓' : 'copy path'}
        </button>
      )}
      <button
        onClick={async () => {
          setDeleting(true)
          await onDelete()
          setDeleting(false)
        }}
        title="Delete"
        disabled={deleting}
        className="opacity-0 group-hover:opacity-100 text-[10px] px-1.5 py-0.5 rounded bg-[var(--surface-2)] border border-[var(--border)] text-[#ff7b72] hover:bg-[#ff7b7222] transition-all flex-shrink-0 disabled:opacity-40"
      >
        {deleting ? '…' : 'delete'}
      </button>
    </div>
  )
}

// ── Section wrapper ───────────────────────────────────────────────────────────
function Section({ title, icon, badge, children }) {
  return (
    <div className="bg-[var(--surface)] border border-[var(--border)] rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-[var(--border)]">
        <span className="text-sm">{icon}</span>
        <span className="text-sm font-semibold text-[var(--text)]">{title}</span>
        {badge != null && (
          <span className="ml-auto text-xs bg-[var(--surface-2)] border border-[var(--border)] text-[var(--text-2)] px-2 py-0.5 rounded-full">
            {badge}
          </span>
        )}
      </div>
      <div className="p-4 space-y-4">{children}</div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function UploadPage() {
  const [wordlists, setWordlists]         = useState([])
  const [workflows, setWorkflows]         = useState([])
  const [wlUploads, setWlUploads]         = useState([])   // [{name, status, error}]
  const [wfUploads, setWfUploads]         = useState([])
  const [loadingWl, setLoadingWl]         = useState(true)
  const [loadingWf, setLoadingWf]         = useState(true)

  // ── Fetch ──────────────────────────────────────────────────────────────────
  const fetchWordlists = useCallback(async () => {
    setLoadingWl(true)
    try {
      const r = await fetch(`${API}/wordlists`)
      if (r.ok) setWordlists(await r.json())
    } finally { setLoadingWl(false) }
  }, [])

  const fetchWorkflows = useCallback(async () => {
    setLoadingWf(true)
    try {
      const r = await fetch(`${API}/workflows`)
      if (r.ok) {
        const names = await r.json()
        // Enrich with size
        const items = await Promise.all(names.map(async name => {
          try {
            const r2 = await fetch(`${API}/workflows/${name}`)
            const text = r2.ok ? await r2.text() : ''
            return { name, size: new TextEncoder().encode(text).length }
          } catch { return { name, size: 0 } }
        }))
        setWorkflows(items)
      }
    } finally { setLoadingWf(false) }
  }, [])

  useEffect(() => {
    fetchWordlists()
    fetchWorkflows()
  }, [fetchWordlists, fetchWorkflows])

  // ── Upload helpers ─────────────────────────────────────────────────────────
  const uploadFiles = useCallback(async (files, endpoint, setUploads, onDone) => {
    const rows = files.map(f => ({ name: f.name, status: 'loading', error: '' }))
    setUploads(prev => [...prev, ...rows])

    await Promise.all(files.map(async (file, i) => {
      const fd = new FormData()
      fd.append('file', file)
      try {
        const r = await fetch(`${API}${endpoint}`, { method: 'POST', body: fd })
        const json = await r.json()
        if (!r.ok) throw new Error(json.detail || r.statusText)
        setUploads(prev => prev.map(row =>
          row.name === file.name && row.status === 'loading'
            ? { ...row, status: 'done' }
            : row
        ))
      } catch (err) {
        setUploads(prev => prev.map(row =>
          row.name === file.name && row.status === 'loading'
            ? { ...row, status: 'error', error: err.message }
            : row
        ))
      }
    }))
    onDone()
  }, [])

  const handleWordlistFiles = useCallback((files) => {
    uploadFiles(files, '/wordlists', setWlUploads, fetchWordlists)
  }, [uploadFiles, fetchWordlists])

  const handleWorkflowFiles = useCallback((files) => {
    uploadFiles(files, '/upload/workflow', setWfUploads, fetchWorkflows)
  }, [uploadFiles, fetchWorkflows])

  // ── Delete ─────────────────────────────────────────────────────────────────
  const deleteWordlist = useCallback(async (name) => {
    await fetch(`${API}/wordlists/${encodeURIComponent(name)}`, { method: 'DELETE' })
    await fetchWordlists()
  }, [fetchWordlists])

  const deleteWorkflow = useCallback(async (name) => {
    await fetch(`${API}/workflows/${encodeURIComponent(name)}`, { method: 'DELETE' })
    await fetchWorkflows()
  }, [fetchWorkflows])

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <div className="max-w-4xl mx-auto px-6 py-8 space-y-6">
      <div>
        <h1 className="text-lg font-bold text-[var(--text)]">Upload</h1>
        <p className="text-xs text-[var(--text-2)] mt-0.5">
          Wordlists are saved to <code className="text-[var(--accent)]">/app/wordlists/</code> — reference them directly in workflow vars.
          Workflows are saved to <code className="text-[var(--accent)]">/app/workflows/</code>.
        </p>
      </div>

      {/* ── Wordlists ── */}
      <Section title="Wordlists" icon="≡" badge={wordlists.length}>
        <DropZone
          accept=".txt"
          label="Drop .txt wordlist files here"
          hint="Subdomain lists, directory lists, parameter wordlists — any .txt file · max 100 MB"
          onFiles={handleWordlistFiles}
        />

        {/* Upload feedback */}
        {wlUploads.length > 0 && (
          <div className="space-y-0.5">
            {wlUploads.map((u, i) => <UploadRow key={i} {...u} />)}
          </div>
        )}

        {/* File list */}
        {loadingWl ? (
          <p className="text-xs text-[var(--text-2)] px-3">Loading…</p>
        ) : wordlists.length === 0 ? (
          <p className="text-xs text-[var(--text-2)] px-3">No wordlists uploaded yet</p>
        ) : (
          <div className="border border-[var(--border)] rounded divide-y divide-[var(--surface-2)]">
            {wordlists.map(w => (
              <FileItem
                key={w.name}
                name={w.name}
                size={w.size}
                lines={w.lines}
                path={`/app/wordlists/${w.name}`}
                onDelete={() => deleteWordlist(w.name)}
              />
            ))}
          </div>
        )}
      </Section>

      {/* ── Workflows ── */}
      <Section title="Workflows" icon="◈" badge={workflows.length}>
        <DropZone
          accept=".yaml,.yml"
          label="Drop .yaml workflow files here"
          hint="Custom workflow YAML files · max 100 MB"
          onFiles={handleWorkflowFiles}
        />

        {/* Upload feedback */}
        {wfUploads.length > 0 && (
          <div className="space-y-0.5">
            {wfUploads.map((u, i) => <UploadRow key={i} {...u} />)}
          </div>
        )}

        {/* File list */}
        {loadingWf ? (
          <p className="text-xs text-[var(--text-2)] px-3">Loading…</p>
        ) : workflows.length === 0 ? (
          <p className="text-xs text-[var(--text-2)] px-3">No workflows found</p>
        ) : (
          <div className="border border-[var(--border)] rounded divide-y divide-[var(--surface-2)]">
            {workflows.map(w => (
              <FileItem
                key={w.name}
                name={w.name}
                size={w.size}
                onDelete={() => deleteWorkflow(w.name)}
              />
            ))}
          </div>
        )}
      </Section>
    </div>
  )
}
