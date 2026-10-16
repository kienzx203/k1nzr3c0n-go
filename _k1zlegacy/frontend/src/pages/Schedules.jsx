import React, { useEffect, useState, useCallback } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../api.js'
import { timeAgo } from '../utils.js'

const CRON_PRESETS = [
  { label: 'Every 6 hours',  value: '0 */6 * * *' },
  { label: 'Daily 09:00',    value: '0 9 * * *' },
  { label: 'Daily 22:00',    value: '0 22 * * *' },
  { label: 'Mon 09:00',      value: '0 9 * * 1' },
  { label: '1st of month',   value: '0 9 1 * *' },
]

const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']

// "0 9 * * 1" → "Mons 09:00" · "0 (every)6 * * *" → "every 6h"
export function cronLabel(expr) {
  const p = (expr || '').trim().split(/\s+/)
  if (p.length !== 5) return expr || '—'
  const [m, h, dom, , dow] = p
  const time = h !== '*' && m !== '*' ? `${h.padStart(2, '0')}:${m.padStart(2, '0')}` : null
  if (m.startsWith('*/')) return `every ${m.slice(2)}m`
  if (h.startsWith('*/')) return `every ${h.slice(2)}h`
  if (dom !== '*') return `day ${dom}${time ? ` ${time}` : ''}`
  if (dow !== '*') return `${DAYS[+dow] ?? dow}${time ? `s ${time}` : 's'}`
  if (time) return `daily ${time}`
  return expr
}

function ScheduleModal({ workflows, initial, editId, onClose, onSaved }) {
  const [form, setForm] = useState({
    name: initial?.name || '',
    target: initial?.target || '',
    workflow: initial?.workflow || workflows[0] || '',
    cron_expr: initial?.cron_expr || '0 9 * * 1',
    varsText: initial?.varsText ?? '',
    alert_new_assets: initial?.alert_new_assets ?? true,
  })
  const [err, setErr] = useState('')
  const [saving, setSaving] = useState(false)

  const set = (k) => (e) => setForm(f => ({ ...f, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value }))

  async function save() {
    setErr(''); setSaving(true)
    try {
      const vars = {}
      for (const line of form.varsText.split('\n')) {
        const i = line.indexOf('=')
        if (i > 0) vars[line.slice(0, i).trim()] = line.slice(i + 1).trim()
      }
      const body = {
        name: form.name, workflow: form.workflow,
        cron_expr: form.cron_expr, vars, alert_new_assets: form.alert_new_assets,
      }
      if (editId != null) {
        await api.patchSchedule(editId, body)
      } else {
        await api.createSchedule({ ...body, target: form.target })
      }
      onSaved()
    } catch (e) {
      setErr(e.message); setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center px-4"
         style={{ background: 'rgba(0,0,0,.55)' }} onClick={onClose}>
      <div className="card w-full max-w-md p-5 fade-in" onClick={e => e.stopPropagation()}>
        <h2 className="text-sm font-bold mb-4" style={{ color: 'var(--text)' }}>
          {editId != null ? 'Edit Schedule' : 'New Schedule'}
        </h2>
        <div className="space-y-3">
          <div>
            <label className="label">Name</label>
            <input className="input" value={form.name} onChange={set('name')} placeholder="weekly-full-recon" />
          </div>
          {!editId && (
            <div>
              <label className="label">Target</label>
              <input className="input font-mono" value={form.target} onChange={set('target')} placeholder="example.com" />
            </div>
          )}
          <div>
            <label className="label">Workflow</label>
            <select className="input" value={form.workflow} onChange={set('workflow')}>
              {workflows.map(w => <option key={w} value={w}>{w}</option>)}
            </select>
          </div>
          <div>
            <label className="label">Cron (local time, 5 fields)</label>
            <input className="input font-mono" value={form.cron_expr} onChange={set('cron_expr')} />
            <p className="text-[10px] mt-1 font-mono" style={{ color: 'var(--accent)' }}>→ {cronLabel(form.cron_expr)}</p>
            <div className="flex gap-1 flex-wrap mt-1.5">
              {CRON_PRESETS.map(p => (
                <button key={p.value} className="btn btn-ghost" style={{ fontSize: 10 }}
                        onClick={() => setForm(f => ({ ...f, cron_expr: p.value }))}>
                  {p.label}
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="label">Var overrides (key=value per line)</label>
            <textarea className="input font-mono" rows={2} value={form.varsText} onChange={set('varsText')}
                      placeholder={'run_nuclei=true\nnuclei_rl=100'} />
          </div>
          <label className="flex items-center gap-2 text-xs cursor-pointer" style={{ color: 'var(--text-2)' }}>
            <input type="checkbox" checked={form.alert_new_assets} onChange={set('alert_new_assets')}
                   className="accent-[#58a6ff]" />
            Webhook alert when new assets are discovered
          </label>
          {err && <p className="text-xs" style={{ color: 'var(--red)' }}>{err}</p>}
        </div>
        <div className="flex justify-end gap-2 mt-5">
          <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" onClick={save}
                  disabled={saving || !form.name || (!editId && !form.target)}>
            {saving ? 'Saving…' : editId != null ? 'Save changes' : 'Create Schedule'}
          </button>
        </div>
      </div>
    </div>
  )
}

export default function Schedules() {
  const [data, setData] = useState(null)
  const [workflows, setWorkflows] = useState([])
  const [modal, setModal] = useState(null)   // {editId?, initial?} | null
  const [lastStatus, setLastStatus] = useState({})
  const [error, setError] = useState('')
  const [params, setParams] = useSearchParams()

  const load = useCallback(() => {
    api.getSchedules().then(setData).catch(e => setError(e.message))
  }, [])

  useEffect(() => {
    load()
    api.getWorkflows().then(setWorkflows).catch(() => {})
    const t = setInterval(load, 10000)
    return () => clearInterval(t)
  }, [load])

  // ?new=<target> from the Targets page → open create modal prefilled
  useEffect(() => {
    const t = params.get('new')
    if (t) setModal({ initial: { target: t } })
  }, [params])

  // last-run status badges
  useEffect(() => {
    if (!data) return
    const withLast = data.items.filter(s => s.last_run_id)
    Promise.all(withLast.map(s => api.getRun(s.last_run_id).catch(() => null)))
      .then(runs => {
        const m = {}
        withLast.forEach((s, i) => { if (runs[i]) m[s.id] = runs[i].status })
        setLastStatus(m)
      })
  }, [data])

  async function toggle(s) {
    await api.patchSchedule(s.id, { enabled: !s.enabled }).catch(e => setError(e.message))
    load()
  }

  async function trigger(s) {
    if (!window.confirm(`Run ${s.workflow} against ${s.target} now?`)) return
    try {
      const r = await api.triggerSchedule(s.id)
      window.location.href = `/#/runs/${r.run_id}`
      load()
    } catch (e) { setError(e.message) }
  }

  async function remove(s) {
    if (!window.confirm(`Delete schedule "${s.name}"?`)) return
    await api.deleteSchedule(s.id).catch(e => setError(e.message))
    load()
  }

  return (
    <div className="p-6 space-y-4">
      <div className="page-header">
        <div>
          <h1 className="page-title">Schedules</h1>
          <p className="page-sub">Continuous recon — cron-driven workflow runs with new-asset alerts</p>
        </div>
        <button className="btn btn-primary" onClick={() => setModal({})}>+ New Schedule</button>
      </div>

      {error && <p className="text-xs" style={{ color: 'var(--red)' }}>{error}</p>}

      {!data ? (
        <div className="card h-32 animate-pulse" />
      ) : data.items.length === 0 ? (
        <div className="card p-10 text-center">
          <p className="text-sm mb-1" style={{ color: 'var(--text-2)' }}>No schedules yet.</p>
          <p className="text-xs mb-4" style={{ color: 'var(--text-3)' }}>
            Schedule a workflow to re-scan a target on a cron — new subdomains/hosts alert via webhook.
          </p>
          <button className="btn btn-primary" onClick={() => setModal({})}>Create first schedule</button>
        </div>
      ) : (
        <div className="card overflow-hidden">
          <table className="table-base">
            <thead>
              <tr>{['Schedule', 'Target', 'Workflow', 'Cadence', 'Next run', 'Last run', ''].map(h => <th key={h}>{h}</th>)}</tr>
            </thead>
            <tbody>
              {data.items.map(s => (
                <tr key={s.id} className="group">
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-2">
                      <span className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                            style={{ background: s.enabled ? 'var(--green)' : 'var(--text-3)' }} />
                      <span className="font-medium" style={{ color: 'var(--text)' }}>{s.name}</span>
                      {s.alert_new_assets && (
                        <span className="text-[9px] px-1.5 py-0.5 rounded-full"
                              style={{ background: 'rgba(88,166,255,.12)', color: 'var(--accent)' }}
                              title="Webhook on new assets">🆕 alert</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-2.5">
                    <Link to={`/targets?sel=${encodeURIComponent(s.target)}`} className="font-mono hover:underline"
                          style={{ color: 'var(--accent)' }}>{s.target}</Link>
                  </td>
                  <td className="px-4 py-2.5" style={{ color: 'var(--text-2)' }}>{s.workflow}</td>
                  <td className="px-4 py-2.5">
                    <span className="font-mono text-[10px]" style={{ color: 'var(--text-3)' }}>{s.cron_expr}</span>
                    <p className="text-[10px]" style={{ color: 'var(--accent)' }}>{cronLabel(s.cron_expr)}</p>
                  </td>
                  <td className="px-4 py-2.5" style={{ color: 'var(--text-2)' }}>
                    {s.enabled && s.next_run_at ? timeAgo(s.next_run_at).replace('ago', 'from now') : '—'}
                  </td>
                  <td className="px-4 py-2.5">
                    {s.last_run_id ? (
                      <span className="flex items-center gap-1.5">
                        <Link to={`/runs/${s.last_run_id}`} className="hover:underline" style={{ color: 'var(--accent)' }}>
                          {timeAgo(s.last_run_at)}
                        </Link>
                        {lastStatus[s.id] && (
                          <span className={`badge badge-${lastStatus[s.id]}`}>{lastStatus[s.id]}</span>
                        )}
                      </span>
                    ) : 'never'}
                  </td>
                  <td className="px-4 py-2.5 text-right whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity">
                    <button className="btn btn-accent mr-1.5" onClick={() => trigger(s)}>Run now</button>
                    <button className="btn btn-ghost mr-1.5"
                            onClick={() => setModal({
                              editId: s.id,
                              initial: {
                                name: s.name, workflow: s.workflow, cron_expr: s.cron_expr,
                                alert_new_assets: s.alert_new_assets,
                                varsText: Object.entries(s.vars || {}).map(([k, v]) => `${k}=${v}`).join('\n'),
                              },
                            })}>Edit</button>
                    <button className={`btn mr-1.5 ${s.enabled ? 'btn-warning' : 'btn-success'}`} onClick={() => toggle(s)}>
                      {s.enabled ? 'Disable' : 'Enable'}
                    </button>
                    <button className="btn btn-ghost" onClick={() => remove(s)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {modal && (
        <ScheduleModal workflows={workflows} editId={modal.editId} initial={modal.initial}
                       onClose={() => { setModal(null); if (params.get('new')) setParams({}) }}
                       onSaved={() => { setModal(null); if (params.get('new')) setParams({}); load() }} />
      )}
    </div>
  )
}
