import React, { useEffect, useState, useCallback } from 'react'
import { api } from '../api.js'
import { timeAgo } from '../utils.js'

function Icon({ d, size = 14 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor"
         strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{d}</svg>
  )
}
const I = {
  wave: <path d="M1.5 8h2l1.5-4 2 8 2-8 1.5 4h4" />,
  play: <path d="M4.5 2.8v10.4L13 8z" />,
  stop: <><rect x="3.5" y="3.5" width="9" height="9" rx="1.2" /></>,
  link: <><path d="M6.5 9.5 9.5 6.5" /><path d="M5 7 3.5 8.5a2.5 2.5 0 0 0 3.5 3.5L8.5 10.5M8 5l1.5-1.5A2.5 2.5 0 0 1 13 7L11.5 8.5" /></>,
}

const methodColor = m => ({
  GET: 'var(--accent)', POST: 'var(--green)', PUT: 'var(--amber)',
  DELETE: 'var(--red)', PATCH: 'var(--orange)',
}[m] || 'var(--text-2)')
const statusColor = c => (c >= 500 ? 'var(--red)' : c >= 400 ? 'var(--amber)' : c > 0 ? 'var(--green)' : 'var(--text-3)')

export default function Traffic() {
  const [items, setItems] = useState([])
  const [host, setHost] = useState('')
  const [detail, setDetail] = useState(null)
  const [capture, setCapture] = useState(null)
  const [loading, setLoading] = useState(false)
  const [rules, setRules] = useState([])
  const [approvals, setApprovals] = useState([])

  const loadApprovals = useCallback(async () => {
    try { setApprovals(await api.listApprovals(true)) } catch {}
  }, [])
  useEffect(() => { loadApprovals(); const t = setInterval(loadApprovals, 3000); return () => clearInterval(t) }, [loadApprovals])

  async function decide(id, decision) {
    try { await api.decideApproval(id, decision); loadApprovals() } catch {}
  }

  const loadRules = useCallback(async () => {
    try { setRules(await api.listRules()) } catch {}
  }, [])
  useEffect(() => { loadRules() }, [loadRules])

  async function addRule(e) {
    e.preventDefault()
    const pattern = e.target.elements.pattern.value.trim()
    const action = e.target.elements.action.value
    if (!pattern) return
    try {
      await api.createRule({ pattern, action })
      e.target.reset()
      loadRules()
    } catch {}
  }

  async function removeRule(id) {
    try { await api.deleteRule(id); loadRules() } catch {}
  }

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params = {}
      if (host) params.host = host
      const r = await api.listTraffic(params)
      setItems(r.items || [])
    } catch {} finally { setLoading(false) }
  }, [host])

  const poll = useCallback(async () => {
    try { setCapture(await api.captureStatus()) } catch {}
  }, [])

  useEffect(() => { load(); poll() }, [load]) // eslint-disable-line
  useEffect(() => {
    const t = setInterval(load, 5000)
    return () => clearInterval(t)
  }, [load])

  async function toggle() {
    try {
      const r = await api.captureToggle(!capture?.enabled)
      setCapture(prev => ({ ...prev, ...r }))
    } catch {}
  }

  async function openDetail(id) {
    try { setDetail(await api.getTraffic(id)) } catch {}
  }

  async function bindToFinding() {
    const fid = prompt('Finding ID để gắn evidence:')
    if (!fid) return
    try {
      await api.bindTraffic({ traffic_id: detail.id, finding_id: +fid })
      load()
      openDetail(detail.id)
    } catch (e) { alert(e.message) }
  }

  const on = !!capture?.enabled

  return (
    <div className="fade-in">
      <div className="flex items-center gap-2.5 mb-4 flex-wrap">
        <span className="p-2 rounded-lg" style={{ background: 'var(--surface-3)', color: 'var(--orange)' }}>
          <Icon d={I.wave} size={17} />
        </span>
        <div>
          <h2 className="text-[15px] font-bold leading-tight">Traffic Evidence</h2>
          <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
            Recording MITM proxy {capture?.addr ? `· ${capture.addr}` : ''} · {items.length} pairs captured
          </p>
        </div>
        <span className={`badge badge-${on ? 'running' : 'cancelled'} text-[10px] ml-1`}>
          {on ? 'capture ON' : 'capture OFF'}
        </span>
        <div className="flex gap-2 ml-auto">
          <input className="input w-44 text-[11.5px]" placeholder="filter host…" value={host}
                 onChange={e => setHost(e.target.value)} />
          {on
            ? <button className="btn btn-danger flex items-center gap-1.5" onClick={toggle}><Icon d={I.stop} /> Stop</button>
            : <button className="btn btn-primary flex items-center gap-1.5" onClick={toggle}><Icon d={I.play} /> Start capture</button>}
        </div>
      </div>

      {/* pending approvals */}
      {approvals.length > 0 && (
        <div className="card p-3 mb-4 fade-in" style={{ borderColor: 'var(--amber)' }}>
          <p className="text-[10px] uppercase tracking-wider font-semibold mb-2" style={{ color: 'var(--amber)' }}>
            ⏸ Pending approvals — request đang bị GIỮ chờ quyết định
          </p>
          <div className="flex flex-col gap-1.5">
            {approvals.map(a => (
              <div key={a.id} className="flex items-center gap-2 text-[11px]">
                <span className="font-mono" style={{ color: 'var(--text-2)' }}>{a.method}</span>
                <span className="font-mono truncate max-w-[380px]">{a.host}{a.path}</span>
                <span className="ml-auto flex gap-1.5">
                  <button className="btn btn-primary text-[10px] px-2 py-1" onClick={() => decide(a.id, 'approve')}>✓ Approve</button>
                  <button className="btn btn-danger text-[10px] px-2 py-1" onClick={() => decide(a.id, 'deny')}>✕ Deny</button>
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* rules */}
      <div className="card p-3 mb-4">
        <div className="flex items-center gap-3 mb-2">
          <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-2)' }}>
            Traffic rules — chặn (block) host khớp pattern
          </p>
          <form onSubmit={addRule} className="flex gap-1.5 ml-auto">
            <input name="pattern" className="input w-52 text-[11px]" placeholder="pattern, vd: .gov.vn" />
            <select name="action" className="input w-20 text-[11px]">
              <option value="block">block</option>
              <option value="flag">flag</option>
              <option value="hold">hold</option>
            </select>
            <button className="btn btn-accent text-[11px]" type="submit">Add</button>
          </form>
        </div>
        {rules.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {rules.map(r => (
              <span key={r.id} className="badge text-[10px] font-mono cursor-pointer group"
                    style={{ background: r.action === 'block' ? 'rgba(248,81,73,.12)' : 'rgba(240,180,41,.12)',
                             color: r.action === 'block' ? 'var(--red)' : 'var(--amber)' }}
                    title="click để xóa" onClick={() => removeRule(r.id)}>
                {r.action === 'block' ? '⛔' : '⚑'} {r.pattern} <span className="opacity-0 group-hover:opacity-100">✕</span>
              </span>
            ))}
          </div>
        )}
      </div>

      <div className="grid gap-4" style={{ gridTemplateColumns: '1fr 1fr' }}>
        {/* list */}
        <div className="card overflow-auto" style={{ padding: 0, maxHeight: '68vh' }}>
          <table className="w-full text-[11.5px]" style={{ borderCollapse: 'collapse' }}>
            <thead>
              <tr className="text-left text-[9.5px] uppercase tracking-wider sticky top-0"
                  style={{ color: 'var(--text-3)', background: 'var(--surface)' }}>
                {['#', 'Method', 'Host', 'Path', 'Code', 'Ev'].map(h => (
                  <th className="px-3 py-2.5 font-semibold" style={{ borderBottom: '1px solid var(--border)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading && !items.length && (
                <tr><td colSpan={6} className="px-3 py-8 text-center" style={{ color: 'var(--text-3)' }}>loading…</td></tr>
              )}
              {items.map(t => (
                <tr key={t.id} onClick={() => openDetail(t.id)}
                    className="cursor-pointer transition-colors hover:bg-[var(--surface-2)]"
                    style={{
                      borderBottom: '1px solid var(--border)',
                      background: detail?.id === t.id ? 'var(--surface-3)' : undefined,
                    }}>
                  <td className="px-3 py-2 font-mono text-[10px]" style={{ color: 'var(--text-3)' }}>{t.id}</td>
                  <td className="px-3 py-2">
                    <span className="badge text-[9px] font-mono" style={{ background: 'var(--surface-2)', color: methodColor(t.method) }}>
                      {t.method}
                    </span>
                  </td>
                  <td className="px-3 py-2 font-mono truncate max-w-[160px]">{t.host}</td>
                  <td className="px-3 py-2 truncate max-w-[200px]" style={{ color: 'var(--text-2)' }}>{t.path}</td>
                  <td className="px-3 py-2 font-mono font-semibold" style={{ color: statusColor(t.status_code) }}>
                    {t.status_code || '—'}
                  </td>
                  <td className="px-3 py-2 font-mono text-[10px]">
                    {t.finding_id ? <span style={{ color: 'var(--green)' }}>#{t.finding_id}</span> : ''}
                  </td>
                </tr>
              ))}
              {!loading && !items.length && (
                <tr><td colSpan={6} className="px-4 py-10 text-center text-[11.5px] leading-relaxed" style={{ color: 'var(--text-3)' }}>
                  Chưa có traffic. Bật <b>Start capture</b> rồi chạy workflow — HTTP của tool đi qua proxy
                  và được ghi lại làm evidence (tự gắn run id).
                </td></tr>
              )}
            </tbody>
          </table>
        </div>

        {/* detail */}
        <div className="card overflow-auto" style={{ padding: 0, maxHeight: '68vh' }}>
          {!detail && (
            <div className="px-4 py-10 text-center text-[11.5px]" style={{ color: 'var(--text-3)' }}>
              Chọn một bản ghi bên trái để xem request / response đầy đủ.
            </div>
          )}
          {detail && (
            <>
              <div className="card-header flex items-center gap-2 flex-wrap" style={{ padding: '10px 14px' }}>
                <span className="badge text-[9.5px] font-mono" style={{ background: 'var(--surface-2)', color: methodColor(detail.method) }}>
                  {detail.method}
                </span>
                <span className="font-mono text-[11.5px] truncate">{detail.host}{detail.path}</span>
                <span className="font-mono text-[11px] font-bold" style={{ color: statusColor(detail.status_code) }}>
                  {detail.status_code || '—'}
                </span>
                <span className="text-[9.5px] ml-auto" style={{ color: 'var(--text-3)' }}>{timeAgo(detail.created_at)}</span>
              </div>
              <div className="px-3.5 py-3">
                <p className="text-[9.5px] font-bold uppercase tracking-wider mb-1.5" style={{ color: 'var(--green)' }}>── Request ──</p>
                <pre className="m-0 whitespace-pre-wrap text-[10.5px] leading-relaxed font-mono"
                     style={{ color: 'var(--text-2)' }}>{detail.request || '(empty)'}</pre>
                <p className="text-[9.5px] font-bold uppercase tracking-wider mb-1.5 mt-4" style={{ color: 'var(--green)' }}>── Response ──</p>
                <pre className="m-0 whitespace-pre-wrap text-[10.5px] leading-relaxed font-mono"
                     style={{ color: 'var(--text-2)' }}>{detail.response || '(empty)'}</pre>
              </div>
              <div className="px-3.5 py-2.5 border-t flex items-center gap-2" style={{ borderColor: 'var(--border)' }}>
                {detail.finding_id ? (
                  <span className="badge badge-completed text-[10px]">evidence → finding #{detail.finding_id}</span>
                ) : (
                  <button className="btn btn-accent flex items-center gap-1.5 text-[11px]" onClick={bindToFinding}>
                    <Icon d={I.link} size={12} /> Bind to finding
                  </button>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
