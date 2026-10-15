import React, { useEffect, useState, useCallback } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { api } from '../api.js'
import { timeAgo } from '../utils.js'

const MODE_META = {
  bounty: { label: 'BOUNTY', color: 'var(--green)' },
  vdp:    { label: 'VDP',    color: 'var(--accent)' },
  oos:    { label: 'OOS',    color: 'var(--red)' },
}

function ModeBadge({ mode }) {
  const m = MODE_META[mode] || MODE_META.bounty
  return (
    <span className="text-[9px] font-bold px-1.5 py-0.5 rounded-full border"
          style={{ color: m.color, borderColor: m.color, background: 'transparent' }}>
      {m.label}
    </span>
  )
}

function RegisterModal({ onClose, onSaved }) {
  const [form, setForm] = useState({ name: '', mode: 'bounty', scopeText: '', notes: '' })
  const [err, setErr] = useState('')
  const [saving, setSaving] = useState(false)

  async function save() {
    setErr(''); setSaving(true)
    try {
      const scope = form.scopeText.split('\n').map(s => s.trim()).filter(Boolean)
      await api.createTarget({ name: form.name.trim().toLowerCase(), mode: form.mode, scope, notes: form.notes || null })
      onSaved(form.name.trim().toLowerCase())
    } catch (e) {
      setErr(e.message); setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center px-4"
         style={{ background: 'rgba(0,0,0,.55)' }} onClick={onClose}>
      <div className="card w-full max-w-md p-5 fade-in" onClick={e => e.stopPropagation()}>
        <h2 className="text-sm font-bold mb-4" style={{ color: 'var(--text)' }}>Register Target</h2>
        <div className="space-y-3">
          <div>
            <label className="label">Primary domain</label>
            <input className="input font-mono" value={form.name}
                   onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="example.com" />
          </div>
          <div>
            <label className="label">Engagement mode</label>
            <div className="flex gap-1">
              {Object.entries(MODE_META).map(([key, m]) => (
                <button key={key}
                  className="btn"
                  style={form.mode === key
                    ? { color: m.color, borderColor: m.color, background: 'transparent' }
                    : { color: 'var(--text-3)' }}
                  onClick={() => setForm(f => ({ ...f, mode: key }))}>
                  {m.label}
                </button>
              ))}
            </div>
            {form.mode === 'oos' && (
              <p className="text-[10px] mt-1.5" style={{ color: 'var(--red)' }}>
                OOS = deny-wins: every run attempt against this target will be blocked.
              </p>
            )}
          </div>
          <div>
            <label className="label">Scope patterns (one per line)</label>
            <textarea className="input font-mono" rows={3} value={form.scopeText}
                      onChange={e => setForm(f => ({ ...f, scopeText: e.target.value }))}
                      placeholder={'example.com          (apex + all subs)\n*.example.com        (single-label subs only)\nstaging.example.net  (exact host)'} />
          </div>
          <div>
            <label className="label">Notes</label>
            <textarea className="input" rows={2} value={form.notes}
                      onChange={e => setForm(f => ({ ...f, notes: e.target.value }))}
                      placeholder="Program URL, rules of engagement…" />
          </div>
          {err && <p className="text-xs" style={{ color: 'var(--red)' }}>{err}</p>}
        </div>
        <div className="flex justify-end gap-2 mt-5">
          <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" onClick={save} disabled={saving || !form.name}>
            {saving ? 'Saving…' : 'Register'}
          </button>
        </div>
      </div>
    </div>
  )
}

function TargetDetail({ name, onChanged, onDeleted }) {
  const [detail, setDetail] = useState(null)
  const [audit, setAudit] = useState(null)
  const [scopeText, setScopeText] = useState(null)
  const [checkHost, setCheckHost] = useState('')
  const [checkResult, setCheckResult] = useState(null)
  const [newAssets, setNewAssets] = useState(null)
  const [launching, setLaunching] = useState(false)
  const [err, setErr] = useState('')
  const navigate = useNavigate()

  useEffect(() => {
    api.getTarget(name).then(d => { setDetail(d); setScopeText((d.scope || []).join('\n')) }).catch(e => setErr(e.message))
    api.getTargetAudit(name).then(setAudit).catch(() => {})
    api.targetNewAssets(name).then(setNewAssets).catch(() => {})
  }, [name])

  async function runNow() {
    if (!window.confirm(`Launch 01-full-recon-pipeline against ${name} now?`)) return
    setLaunching(true)
    try {
      const r = await api.createRun({ workflow: '01-full-recon-pipeline.yaml', target: name })
      navigate(`/runs/${r.id}`)
    } catch (e) {
      setErr(e.message); setLaunching(false)
    }
  }

  async function saveScope() {
    setErr('')
    try {
      const scope = scopeText.split('\n').map(s => s.trim()).filter(Boolean)
      await api.patchTarget(name, { scope })
      onChanged()
      api.getTarget(name).then(setDetail).catch(() => {})
    } catch (e) { setErr(e.message) }
  }

  async function setMode(mode) {
    try { await api.patchTarget(name, { mode }); onChanged(); api.getTarget(name).then(setDetail).catch(() => {}) }
    catch (e) { setErr(e.message) }
  }

  async function runCheck() {
    if (!checkHost.trim()) return
    try { setCheckResult(await api.scopeCheck(checkHost.trim())) } catch (e) { setErr(e.message) }
  }

  async function remove() {
    if (!window.confirm(`Unregister target ${name}? Run history is kept.`)) return
    await api.deleteTarget(name).catch(e => setErr(e.message))
    onDeleted()
  }

  if (!detail) return <div className="card p-6 animate-pulse h-40" />

  return (
    <div className="space-y-4 fade-in">
      {/* Header */}
      <div className="card p-4">
        <div className="flex items-center gap-3 flex-wrap">
          <h2 className="text-base font-bold font-mono" style={{ color: 'var(--text)' }}>{detail.name}</h2>
          <ModeBadge mode={detail.mode} />
          <div className="flex gap-1 ml-auto">
            {Object.entries(MODE_META).map(([key]) => key !== detail.mode && (
              <button key={key} className="btn btn-ghost" style={{ fontSize: 10 }} onClick={() => setMode(key)}>
                → {MODE_META[key].label}
              </button>
            ))}
            <button className="btn btn-danger" style={{ fontSize: 10 }} onClick={remove}>Unregister</button>
          </div>
        </div>
        <div className="flex gap-5 mt-3 text-xs" style={{ color: 'var(--text-2)' }}>
          <span>{detail.total_runs ?? 0} runs</span>
          <span style={{ color: (detail.open_vulns ?? 0) > 0 ? 'var(--red)' : undefined }}>
            {detail.open_vulns ?? 0} open vulns
          </span>
          <span>last: {detail.last_run_at ? timeAgo(detail.last_run_at) : 'never'}</span>
          {newAssets && newAssets.total > 0 && (
            <span style={{ color: 'var(--green)' }}>+{newAssets.total} new assets</span>
          )}
        </div>
        <div className="flex gap-2 mt-3">
          <button className="btn btn-primary" onClick={runNow} disabled={launching}>
            {launching ? 'Launching…' : '▶ Run recon now'}
          </button>
          <button className="btn btn-accent" onClick={() => navigate(`/schedules?new=${encodeURIComponent(name)}`)}>
            🕘 New schedule
          </button>
        </div>
        {detail.notes && <p className="text-xs mt-2" style={{ color: 'var(--text-3)' }}>{detail.notes}</p>}
      </div>

      {/* Scope editor */}
      <div className="card overflow-hidden">
        <div className="card-header">
          <h3 className="section-title">Scope (deny-wins)</h3>
          <button className="btn btn-accent" onClick={saveScope}>Save scope</button>
        </div>
        <div className="p-4">
          <textarea className="input font-mono" rows={4} value={scopeText ?? ''}
                    onChange={e => setScopeText(e.target.value)}
                    placeholder={'example.com\n*.example.com'} />
          <p className="text-[10px] mt-1.5" style={{ color: 'var(--text-3)' }}>
            apex = domain + all subs · *.domain = single-label subs only · OOS targets block all runs
          </p>
          {err && <p className="text-xs mt-2" style={{ color: 'var(--red)' }}>{err}</p>}
        </div>
      </div>

      {/* Ad-hoc scope check */}
      <div className="card p-4">
        <h3 className="section-title mb-2">Scope check</h3>
        <div className="flex gap-2">
          <input className="input font-mono" placeholder="host.example.com" value={checkHost}
                 onChange={e => setCheckHost(e.target.value)}
                 onKeyDown={e => e.key === 'Enter' && runCheck()} />
          <button className="btn btn-accent" onClick={runCheck}>Check</button>
        </div>
        {checkResult && (
          <p className="text-xs mt-2 font-mono" style={{ color: checkResult.in_scope ? 'var(--green)' : 'var(--red)' }}>
            {checkResult.in_scope ? '✓ IN SCOPE' : checkResult.denied ? '✗ DENIED (OOS)' : '✗ OUT OF SCOPE'} — {checkResult.reason}
          </p>
        )}
      </div>

      {/* Recent runs */}
      {(detail.recent_runs || []).length > 0 && (
        <div className="card overflow-hidden">
          <div className="card-header"><h3 className="section-title">Recent runs</h3></div>
          <table className="table-base">
            <thead><tr>{['Run', 'Workflow', 'Status', 'Started'].map(h => <th key={h}>{h}</th>)}</tr></thead>
            <tbody>
              {detail.recent_runs.map(r => (
                <tr key={r.id}>
                  <td className="px-4 py-2 font-mono">
                    <Link to={`/runs/${r.id}`} className="hover:underline" style={{ color: 'var(--accent)' }}>{r.id}</Link>
                  </td>
                  <td className="px-4 py-2" style={{ color: 'var(--text-2)' }}>{r.workflow}</td>
                  <td className="px-4 py-2"><span className={`badge badge-${r.status}`}>{r.status}</span></td>
                  <td className="px-4 py-2" style={{ color: 'var(--text-2)' }}>{timeAgo(r.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* New assets — continuous recon feed */}
      {newAssets && newAssets.items.length > 0 && (
        <div className="card overflow-hidden">
          <div className="card-header">
            <h3 className="section-title">New assets discovered</h3>
            <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>
              first-seen across all runs — review & scope them
            </span>
          </div>
          <div className="p-3 flex flex-wrap gap-1.5">
            {newAssets.items.slice(0, 60).map(a => (
              <span key={a.id} className="inline-flex items-center gap-1.5 text-[10px] font-mono px-2 py-1 rounded border"
                    style={{ color: 'var(--text-2)', borderColor: 'var(--border)', background: 'var(--bg-soft)' }}
                    title={`first seen ${a.first_seen?.replace('T', ' ').slice(0, 16)} · run ${a.run_id}`}>
                <span className="w-1.5 h-1.5 rounded-full" style={{ background: 'var(--green)' }} />
                {a.host}
                <span style={{ color: 'var(--text-3)' }}>{a.kind}</span>
              </span>
            ))}
            {newAssets.items.length > 60 && (
              <span className="text-[10px] self-center" style={{ color: 'var(--text-3)' }}>
                +{newAssets.items.length - 60} more
              </span>
            )}
          </div>
        </div>
      )}

      {/* Audit trail */}
      {audit && audit.items.length > 0 && (
        <div className="card overflow-hidden">
          <div className="card-header"><h3 className="section-title">Scope audit trail</h3></div>
          <table className="table-base">
            <thead><tr>{['When', 'Action', 'Result', 'Detail'].map(h => <th key={h}>{h}</th>)}</tr></thead>
            <tbody>
              {audit.items.slice(0, 20).map(a => (
                <tr key={a.id}>
                  <td className="px-4 py-2 whitespace-nowrap" style={{ color: 'var(--text-3)' }}>{a.ts?.replace('T', ' ').slice(0, 16)}</td>
                  <td className="px-4 py-2" style={{ color: 'var(--text-2)' }}>{a.action}</td>
                  <td className="px-4 py-2 font-bold" style={{ color: a.result === 'denied' ? 'var(--red)' : 'var(--green)' }}>
                    {a.result}
                  </td>
                  <td className="px-4 py-2" style={{ color: 'var(--text-3)' }}>{a.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export default function Targets() {
  const [data, setData] = useState(null)
  const [showModal, setShowModal] = useState(false)
  const [params, setParams] = useSearchParams()
  const selected = params.get('sel') || null

  const load = useCallback(() => {
    api.getTargets().then(setData).catch(() => {})
  }, [])

  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t) }, [load])

  return (
    <div className="p-6 space-y-4">
      {!selected ? (
        <>
          <div className="page-header">
            <div>
              <h1 className="page-title">Targets</h1>
              <p className="page-sub">Target-centric view — scope definitions, run history, findings per engagement</p>
            </div>
            <button className="btn btn-primary" onClick={() => setShowModal(true)}>+ Register Target</button>
          </div>

          {!data ? (
            <div className="card h-32 animate-pulse" />
          ) : data.items.length === 0 ? (
            <div className="card p-10 text-center">
              <p className="text-sm mb-1" style={{ color: 'var(--text-2)' }}>No registered targets.</p>
              <p className="text-xs mb-4" style={{ color: 'var(--text-3)' }}>
                Register targets to define scope (deny-wins) and get a per-target engagement view.
              </p>
              <button className="btn btn-primary" onClick={() => setShowModal(true)}>Register first target</button>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
              {data.items.map(t => (
                <button key={t.name} className="card card-hover p-4 text-left"
                        onClick={() => setParams({ sel: t.name })}>
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-sm" style={{ color: 'var(--text)' }}>{t.name}</span>
                    <ModeBadge mode={t.mode} />
                  </div>
                  <div className="flex gap-4 mt-3 text-[11px]" style={{ color: 'var(--text-2)' }}>
                    <span>{t.total_runs} runs</span>
                    <span style={{ color: t.open_vulns > 0 ? 'var(--red)' : undefined }}>
                      {t.open_vulns} open vulns
                    </span>
                  </div>
                  <p className="text-[10px] mt-2" style={{ color: 'var(--text-3)' }}>
                    {t.last_run_at ? `last run ${timeAgo(t.last_run_at)} · ${t.last_status}` : 'never scanned'}
                  </p>
                </button>
              ))}
            </div>
          )}
        </>
      ) : (
        <>
          <div className="flex items-center gap-2">
            <button className="btn btn-ghost" onClick={() => setParams({})}>← All targets</button>
          </div>
          <TargetDetail name={selected} onChanged={load} onDeleted={() => { setParams({}); load() }} />
        </>
      )}

      {showModal && (
        <RegisterModal onClose={() => setShowModal(false)}
                       onSaved={(name) => { setShowModal(false); load(); setParams({ sel: name }) }} />
      )}
    </div>
  )
}
