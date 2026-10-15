import React, { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api.js'
import { MAX_BATCH, parseTargetList } from '../utils/targets.js'

const AUTH_VARS = ['session_cookie', 'auth_header', 'custom_header']

// Maps workflow var name → API key provider (stored in Keys page, injected at run time by tasks.py)
const VAR_AUTO_INJECT = {
  chaos_key: 'chaos',
}

// Per-workflow key dependency config (matches TEMPLATE_DEPS in Keys.jsx)
const WORKFLOW_KEY_DEPS = {
  'k1nzr3con.yaml':              { subfinder: true,  autoVars: ['chaos_key'] },
  '01-full-recon-pipeline.yaml': { subfinder: true,  autoVars: ['chaos_key'] },
  '02-js-secrets-recon.yaml':    { subfinder: false, autoVars: [] },
  '03-param-discovery.yaml':     { subfinder: false, autoVars: [] },
}

const SUBFINDER_TOTAL = 21

const PRIORITY_VARS = [
  'method', 'katana_depth', 'katana_concurrency', 'katana_timeout',
  'arjun_rate', 'arjun_threads', 'ffuf_threads', 'ffuf_filter_size',
  'param_wordlist', 'dir_wordlist', 'dirsearch_threads', 'ferox_threads',
  'httpx_threads', 'httpx_timeout', 'nuclei_rl', 'nuclei_timeout',
  'chaos_key', 'naabu_rate', 'naabu_top_ports', 'rustscan_batch',
]

const VAR_LABEL = {
  method: 'Method',
  katana_depth: 'Katana depth',
  katana_concurrency: 'Katana concurrency',
  katana_timeout: 'Katana timeout',
  arjun_rate: 'Arjun rate limit',
  arjun_threads: 'Arjun threads',
  ffuf_threads: 'FFUF threads',
  ffuf_filter_size: 'FFUF filter size',
  param_wordlist: 'Param wordlist',
  dir_wordlist: 'Dir wordlist',
  dirsearch_threads: 'Dirsearch threads',
  ferox_threads: 'Feroxbuster threads',
  httpx_threads: 'HTTPX threads',
  httpx_timeout: 'HTTPX timeout',
  nuclei_rl: 'Nuclei rate limit',
  nuclei_timeout: 'Nuclei timeout (s)',
  chaos_key: 'Chaos API key',
  naabu_rate: 'Naabu rate',
  naabu_top_ports: 'Top ports',
  rustscan_batch: 'Rustscan batch',
}

function SectionHeader({ children }) {
  return (
    <div style={{
      fontSize: 10, fontWeight: 700, letterSpacing: '0.09em',
      color: 'var(--text-3)', textTransform: 'uppercase',
      borderBottom: '1px solid #21262d',
      paddingBottom: 6, marginBottom: 10,
    }}>
      {children}
    </div>
  )
}

export default function NewRunModal({ onClose, onCreated }) {
  const navigate = useNavigate()
  const [workflows, setWorkflows]     = useState([])
  const [workflow, setWorkflow]       = useState('')
  const [wfMeta, setWfMeta]           = useState(null)
  const [editedVars, setEditedVars]   = useState({})
  const [raw, setRaw]                 = useState('')
  const [out, setOut]                 = useState('')
  const [continueOnError, setContinueOnError] = useState(false)
  const [resume, setResume]           = useState(false)
  const [loading, setLoading]         = useState(false)
  const [progress, setProgress]       = useState(null)
  const [error, setError]             = useState('')
  const [showAdvanced, setShowAdvanced]   = useState(false)
  const [configuredKeys, setConfiguredKeys] = useState({})   // {provider: true}

  useEffect(() => {
    api.getWorkflows().then(wfs => {
      setWorkflows(wfs)
      if (wfs.length) setWorkflow(wfs[0])
    })
    // Load which keys are configured — used to detect auto-injected vars
    api.getKeys().then(keys => {
      const cfg = {}
      keys.filter(k => k.configured).forEach(k => { cfg[k.provider] = true })
      setConfiguredKeys(cfg)
    }).catch(() => {})
  }, [])

  useEffect(() => {
    if (!workflow) return
    setWfMeta(null)
    setEditedVars({})
    setShowAdvanced(false)
    api.getWorkflow(workflow)
      .then(wf => setWfMeta(wf))
      .catch(() => setWfMeta(null))
  }, [workflow])

  const wfVars = wfMeta?.vars || {}
  const hasAuth     = AUTH_VARS.some(k => k in wfVars)
  const toggleVars  = Object.entries(wfVars).filter(([k]) => k.startsWith('run_'))
  const priTextVars = PRIORITY_VARS.filter(k => k in wfVars && !AUTH_VARS.includes(k))
  const advVars     = Object.keys(wfVars).filter(k =>
    !k.startsWith('run_') && !AUTH_VARS.includes(k) && !PRIORITY_VARS.includes(k)
  )

  const getVar = (k) =>
    editedVars[k] !== undefined ? editedVars[k] : String(wfVars[k] ?? '')
  const setVar = (k, v) =>
    setEditedVars(prev => ({ ...prev, [k]: v }))

  // Returns provider name if this var is auto-injected from a configured key
  const autoProvider = (varName) => {
    const provider = VAR_AUTO_INJECT[varName]
    return (provider && configuredKeys[provider]) ? provider : null
  }

  // Send only overrides that differ from workflow defaults
  const varsList = () => {
    const result = []
    for (const [k, v] of Object.entries(editedVars)) {
      const strV = String(v)
      if (strV === '') continue
      const strDef = String(wfVars[k] ?? '')
      if (strV !== strDef) result.push(`${k}=${strV}`)
    }
    return result
  }

  const targets   = useMemo(() => parseTargetList(raw), [raw])
  const isBatch   = targets.length > 1
  const overLimit = targets.length > MAX_BATCH
  const isMulti   = raw.includes('\n') || raw.includes(',') || /\/\d+/.test(raw)
  const badgeColor = overLimit ? '#f85149' : isBatch ? '#f0b429' : '#3fb950'

  async function submit() {
    if (!workflow || !targets.length) { setError('Workflow and target are required.'); return }
    if (overLimit) { setError(`Too many targets (max ${MAX_BATCH}).`); return }
    setLoading(true); setError('')

    if (!isBatch) {
      try {
        const run = await api.createRun({
          workflow, target: targets[0], vars: varsList(),
          out: out || null, continue_on_error: continueOnError, resume,
        })
        onClose()
        navigate(`/runs/${run.id}`)
      } catch (e) { setError(e.message) }
      setLoading(false)
      return
    }

    setProgress({ done: 0, total: targets.length, errors: 0 })
    let errors = 0
    for (let i = 0; i < targets.length; i++) {
      try {
        await api.createRun({
          workflow, target: targets[i], vars: varsList(),
          out: out || null, continue_on_error: continueOnError, resume,
        })
      } catch { errors++ }
      setProgress({ done: i + 1, total: targets.length, errors })
    }
    setLoading(false)
    onCreated?.()
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div
        className="card w-full shadow-2xl flex flex-col"
        style={{ maxWidth: 560, maxHeight: '92vh' }}
      >
        {/* ── Header ──────────────────────────────────────── */}
        <div className="flex items-start justify-between px-5 py-3.5 border-b border-[var(--border)] flex-shrink-0">
          <div>
            <h2 className="text-sm font-bold text-[var(--text)]">New Run</h2>
            {wfMeta && (
              <p className="text-[10px] text-[var(--text-3)] font-mono mt-0.5">
                {(wfMeta.steps || []).length} steps · {Object.keys(wfVars).length} vars
                {hasAuth && (
                  <span style={{ color: '#58a6ff', marginLeft: 6 }}>· auth support</span>
                )}
              </p>
            )}
          </div>
          <button
            className="btn btn-ghost text-lg leading-none"
            style={{ marginTop: -2 }}
            onClick={onClose}
          >×</button>
        </div>

        {/* ── Scrollable body ──────────────────────────────── */}
        <div className="overflow-y-auto flex-1 px-5 py-4 space-y-5">

          {/* Workflow selector */}
          <div>
            <label className="label">Workflow</label>
            <select
              className="input"
              value={workflow}
              onChange={e => setWorkflow(e.target.value)}
            >
              {workflows.map(w => <option key={w} value={w}>{w}</option>)}
            </select>
            {wfMeta?.description && (
              <p className="text-[10px] text-[var(--text-2)] mt-1.5 leading-relaxed"
                style={{ lineHeight: 1.55 }}>
                {wfMeta.description}
              </p>
            )}

            {/* Key status for selected workflow */}
            {wfMeta && (() => {
              const deps = WORKFLOW_KEY_DEPS[workflow]
              if (!deps) return null
              const keyCount = Object.keys(configuredKeys).length
              const activeAutoVars = (deps.autoVars || []).filter(v => {
                const provider = VAR_AUTO_INJECT[v]
                return provider && configuredKeys[provider]
              })

              return (
                <div style={{
                  display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 5, marginTop: 7,
                }}>
                  {deps.subfinder ? (
                    <>
                      <span style={{
                        fontSize: 9, padding: '2px 7px', borderRadius: 3,
                        background: keyCount > 0 ? '#0a1f0e' : 'var(--bg-soft)',
                        border: `1px solid ${keyCount > 0 ? '#3fb95044' : 'var(--surface-2)'}`,
                        color: keyCount > 0 ? '#3fb950' : 'var(--text-3)',
                      }}>
                        ⚙ subfinder {keyCount}/{SUBFINDER_TOTAL} keys
                      </span>
                      {activeAutoVars.map(v => (
                        <span key={v} style={{
                          fontSize: 9, padding: '2px 7px', borderRadius: 3,
                          fontFamily: 'monospace',
                          background: '#0a192966',
                          border: '1px solid #58a6ff44',
                          color: '#58a6ff',
                        }}>
                          🔑 {v} auto
                        </span>
                      ))}
                      {activeAutoVars.length === 0 && deps.autoVars.length > 0 && (
                        <span style={{
                          fontSize: 9, padding: '2px 7px', borderRadius: 3,
                          fontFamily: 'monospace',
                          background: 'var(--bg-soft)', border: '1px solid #21262d', color: 'var(--text-3)',
                        }}>
                          🔑 {deps.autoVars[0]} not set
                        </span>
                      )}
                    </>
                  ) : (
                    <span style={{ fontSize: 9, color: 'var(--text-3)' }}>
                      ○ no key integration
                      {hasAuth ? ' — auth via Cookie/Bearer below' : ''}
                    </span>
                  )}
                </div>
              )
            })()}
          </div>

          {/* Target */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="label" style={{ margin: 0 }}>Target</label>
              {targets.length > 0 && (
                <span style={{ fontSize: 9, fontWeight: 700, fontFamily: 'monospace', color: badgeColor }}>
                  {overLimit
                    ? `⚠ ${targets.length} — max ${MAX_BATCH}`
                    : isBatch ? `${targets.length} targets → batch`
                    : '1 target'}
                </span>
              )}
            </div>
            <textarea
              className="input"
              rows={isMulti ? 4 : 2}
              placeholder={'https://example.com\n— one per line, comma-separated, or CIDR'}
              value={raw}
              onChange={e => setRaw(e.target.value)}
              style={{ fontFamily: 'monospace', fontSize: 10, resize: 'vertical', lineHeight: 1.6 }}
              autoFocus
            />
            {isBatch && !overLimit && (
              <div style={{ marginTop: 4, lineHeight: 1.8 }}>
                {targets.slice(0, 6).map(t => (
                  <span key={t} style={{
                    display: 'inline-block', marginRight: 4, marginBottom: 2,
                    fontFamily: 'monospace', fontSize: 9, color: '#58a6ff',
                    background: '#0a1929', border: '1px solid #0d2d4a',
                    borderRadius: 3, padding: '1px 6px',
                  }}>{t}</span>
                ))}
                {targets.length > 6 && (
                  <span style={{ fontSize: 9, color: 'var(--text-3)' }}>
                    +{targets.length - 6} more
                  </span>
                )}
              </div>
            )}
            {overLimit && (
              <p className="text-[var(--red)] text-xs mt-1">
                Too many targets. Max {MAX_BATCH} per batch.
              </p>
            )}
          </div>

          {/* ── Auth section ─────────────────────────────── */}
          {hasAuth && (
            <div>
              <SectionHeader>Auth</SectionHeader>
              <div className="space-y-2.5">

                {'session_cookie' in wfVars && (
                  <div>
                    <label style={{
                      fontSize: 10, color: 'var(--text-2)', display: 'flex',
                      alignItems: 'center', gap: 5, marginBottom: 4,
                    }}>
                      <span style={{ fontSize: 13 }}>🍪</span>
                      Cookie
                      <span style={{ color: 'var(--text-3)', fontSize: 9 }}>
                        (Cookie: header)
                      </span>
                    </label>
                    <input
                      className="input"
                      style={{ fontFamily: 'monospace', fontSize: 10 }}
                      placeholder="PHPSESSID=abc123; _session=xyz; remember_token=def456"
                      value={getVar('session_cookie')}
                      onChange={e => setVar('session_cookie', e.target.value)}
                    />
                  </div>
                )}

                {'auth_header' in wfVars && (
                  <div>
                    <label style={{
                      fontSize: 10, color: 'var(--text-2)', display: 'flex',
                      alignItems: 'center', gap: 5, marginBottom: 4,
                    }}>
                      <span style={{ fontSize: 13 }}>🔑</span>
                      Authorization
                      <span style={{ color: 'var(--text-3)', fontSize: 9 }}>
                        (Authorization: header)
                      </span>
                    </label>
                    <input
                      className="input"
                      style={{ fontFamily: 'monospace', fontSize: 10 }}
                      placeholder="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                      value={getVar('auth_header')}
                      onChange={e => setVar('auth_header', e.target.value)}
                    />
                  </div>
                )}

                {'custom_header' in wfVars && (
                  <div>
                    <label style={{
                      fontSize: 10, color: 'var(--text-2)', display: 'flex',
                      alignItems: 'center', gap: 5, marginBottom: 4,
                    }}>
                      <span style={{ fontSize: 13 }}>⊕</span>
                      Custom Header
                      <span style={{ color: 'var(--text-3)', fontSize: 9 }}>
                        (Name: Value)
                      </span>
                    </label>
                    <input
                      className="input"
                      style={{ fontFamily: 'monospace', fontSize: 10 }}
                      placeholder="X-API-Key: mysecret123"
                      value={getVar('custom_header')}
                      onChange={e => setVar('custom_header', e.target.value)}
                    />
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ── Phase toggles ────────────────────────────── */}
          {toggleVars.length > 0 && (
            <div>
              <SectionHeader>
                Phases
                <span style={{ fontWeight: 400, textTransform: 'none', letterSpacing: 0, marginLeft: 6, color: 'var(--border)' }}>
                  click to enable / disable
                </span>
              </SectionHeader>
              <div className="flex flex-wrap gap-1.5">
                {toggleVars.map(([k]) => {
                  const isOn = getVar(k) === 'true'
                  const label = k.replace(/^run_/, '').replace(/_/g, ' ')
                  return (
                    <button
                      key={k}
                      onClick={() => setVar(k, isOn ? 'false' : 'true')}
                      style={{
                        fontSize: 10, padding: '3px 10px', borderRadius: 4,
                        border: `1px solid ${isOn ? '#3fb95055' : 'var(--surface-2)'}`,
                        background: isOn ? '#3fb95014' : 'transparent',
                        color: isOn ? '#3fb950' : 'var(--text-3)',
                        cursor: 'pointer', fontFamily: 'monospace',
                        transition: 'all .12s',
                      }}
                    >
                      {isOn ? '✓' : '○'} {label}
                    </button>
                  )
                })}
              </div>
            </div>
          )}

          {/* ── Priority settings ────────────────────────── */}
          {priTextVars.length > 0 && (
            <div>
              <SectionHeader>Settings</SectionHeader>
              <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(2, 1fr)',
                gap: '8px 16px',
              }}>
                {priTextVars.map(k => {
                  const provider = autoProvider(k)
                  return (
                    <div key={k}>
                      <label style={{
                        fontSize: 9, color: 'var(--text-2)', display: 'flex',
                        alignItems: 'center', gap: 4,
                        textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 3,
                      }}>
                        {VAR_LABEL[k] || k.replace(/_/g, ' ')}
                        {provider && (
                          <span style={{
                            fontSize: 8, padding: '0px 4px', borderRadius: 3,
                            background: '#0a192966', border: '1px solid #58a6ff55',
                            color: '#58a6ff', fontWeight: 700, letterSpacing: 0,
                            textTransform: 'none',
                          }}>🔑 auto</span>
                        )}
                      </label>
                      {provider ? (
                        <div style={{ position: 'relative' }}>
                          <input
                            className="input"
                            style={{ fontSize: 10, padding: '4px 8px', color: '#3fb950', opacity: 0.85 }}
                            value="●●●●●●●●●●●● (from Keys)"
                            readOnly
                            title={`Auto-injected from your saved ${provider} key. Override in Advanced if needed.`}
                          />
                        </div>
                      ) : (
                        <input
                          className="input"
                          style={{ fontSize: 10, padding: '4px 8px' }}
                          value={getVar(k)}
                          onChange={e => setVar(k, e.target.value)}
                        />
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* ── Advanced accordion ───────────────────────── */}
          {advVars.length > 0 && (
            <div>
              <button
                onClick={() => setShowAdvanced(v => !v)}
                style={{
                  fontSize: 10, color: 'var(--text-3)', background: 'none',
                  border: 'none', cursor: 'pointer', padding: 0,
                  display: 'flex', alignItems: 'center', gap: 5,
                }}
              >
                <span style={{ fontSize: 9 }}>{showAdvanced ? '▾' : '▸'}</span>
                Advanced — {advVars.length} more vars
              </button>
              {showAdvanced && (
                <div style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(2, 1fr)',
                  gap: '8px 16px',
                  marginTop: 10,
                }}>
                  {advVars.map(k => (
                    <div key={k}>
                      <label style={{
                        fontSize: 9, color: 'var(--text-2)', display: 'block',
                        textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 3,
                      }}>
                        {k.replace(/_/g, ' ')}
                      </label>
                      <input
                        className="input"
                        style={{ fontSize: 10, padding: '4px 8px' }}
                        value={getVar(k)}
                        onChange={e => setVar(k, e.target.value)}
                      />
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Output dir */}
          <div>
            <label className="label">
              Output dir
              <span className="text-[var(--text-2)] normal-case font-normal ml-1">
                (optional · single target only)
              </span>
            </label>
            <input
              className="input"
              style={{ fontSize: 10 }}
              placeholder="runs/custom-name"
              value={out}
              onChange={e => setOut(e.target.value)}
              disabled={isBatch}
            />
          </div>

          {/* Options */}
          <div className="flex gap-5">
            {[
              ['coe', 'Continue on error', continueOnError, setContinueOnError],
              ['res', 'Resume', resume, setResume],
            ].map(([k, label, val, setter]) => (
              <label key={k}
                className="flex items-center gap-1.5 text-xs text-[var(--text-2)] cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={val}
                  onChange={e => setter(e.target.checked)}
                  className="accent-[var(--accent)]"
                />
                {label}
              </label>
            ))}
          </div>

          {/* Batch progress */}
          {progress && (
            <div>
              <div className="flex justify-between mb-1">
                <span style={{ fontSize: 9, color: 'var(--text-2)', fontFamily: 'monospace' }}>
                  Creating runs… {progress.done}/{progress.total}
                </span>
                {progress.errors > 0 && (
                  <span style={{ fontSize: 9, color: '#f85149', fontFamily: 'monospace' }}>
                    {progress.errors} failed
                  </span>
                )}
              </div>
              <div style={{ background: 'var(--surface-2)', borderRadius: 4, height: 5, overflow: 'hidden' }}>
                <div style={{
                  height: '100%', borderRadius: 4, transition: 'width .15s',
                  background: progress.errors > 0 ? '#f85149' : '#3fb950',
                  width: `${(progress.done / progress.total) * 100}%`,
                }} />
              </div>
            </div>
          )}

          {error && <p className="text-[var(--red)] text-xs">{error}</p>}
        </div>

        {/* ── Footer ──────────────────────────────────────── */}
        <div
          className="flex gap-2 justify-between items-center px-5 py-3.5 border-t border-[var(--border)] flex-shrink-0"
        >
          <div style={{ fontSize: 10, color: 'var(--text-3)', fontFamily: 'monospace' }}>
            {(() => {
              const overrides = varsList().length
              const autoCount = priTextVars.filter(k => autoProvider(k)).length
              const parts = []
              if (overrides > 0) parts.push(`${overrides} override${overrides > 1 ? 's' : ''}`)
              if (autoCount > 0) parts.push(
                <span key="auto" style={{ color: '#58a6ff' }}>
                  {autoCount} auto-injected 🔑
                </span>
              )
              return parts.length > 0 ? parts.reduce((a, b) => [a, ' · ', b]) : 'using workflow defaults'
            })()}
          </div>
          <div className="flex gap-2">
            <button className="btn btn-ghost" onClick={onClose} disabled={loading}>
              Cancel
            </button>
            <button
              className="btn btn-primary"
              onClick={submit}
              disabled={loading || !targets.length || overLimit}
            >
              {loading && progress
                ? `Creating… ${progress.done}/${progress.total}`
                : loading ? 'Starting…'
                : isBatch ? `▶ Run ${targets.length} targets`
                : '▶ Run'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
