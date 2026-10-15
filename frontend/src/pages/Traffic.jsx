import React, { useEffect, useState } from 'react'

const API = '/api/v1'

export default function Traffic() {
  const [items, setItems] = useState([])
  const [host, setHost] = useState('')
  const [detail, setDetail] = useState(null)
  const [capture, setCapture] = useState(null)

  useEffect(() => { load(); poll() }, [host])
  useEffect(() => {
    const t = setInterval(load, 5000)
    return () => clearInterval(t)
  }, [host])

  async function load() {
    const params = new URLSearchParams()
    if (host) params.set('host', host)
    const r = await fetch(`${API}/traffic?${params}`)
    setItems((await r.json()).items || [])
  }
  async function poll() {
    const r = await fetch(`${API}/capture/status`)
    setCapture(await r.json())
  }
  async function toggle() {
    const r = await fetch(`${API}/capture/toggle`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: !capture?.enabled }),
    })
    if (r.ok) poll()
  }
  async function openDetail(id) {
    const r = await fetch(`${API}/traffic/${id}`)
    setDetail(await r.json())
  }

  const statusColor = c => (c >= 500 ? '#f85149' : c >= 400 ? '#d29922' : '#3fb950')

  return (
    <div>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 14, flexWrap: 'wrap' }}>
        <h2 style={{ margin: 0 }}>Traffic Evidence</h2>
        <span style={{ color: capture?.enabled ? '#3fb950' : '#6e7681', fontSize: 12 }}>
          ● capture {capture?.enabled ? 'ON' : 'OFF'} {capture?.addr ? `(${capture.addr})` : ''}
        </span>
        <button className="btn" onClick={toggle}>{capture?.enabled ? 'Stop' : 'Start'} capture</button>
        <input style={{ marginLeft: 'auto', width: 220 }} placeholder="filter host…"
               value={host} onChange={e => setHost(e.target.value)} />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
        <div style={{ border: '1px solid #232a3a', borderRadius: 8, maxHeight: '70vh', overflowY: 'auto' }}>
          <table style={{ width: '100%', fontSize: 12, borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ textAlign: 'left', color: '#8b949e', position: 'sticky', top: 0, background: '#0d1117' }}>
                <th style={{ padding: 8 }}>#</th><th>Host</th><th>Method</th><th>Path</th><th>Status</th><th>Ev</th>
              </tr>
            </thead>
            <tbody>
              {items.map(t => (
                <tr key={t.id} onClick={() => openDetail(t.id)}
                    style={{ borderBottom: '1px solid #1b2230', cursor: 'pointer' }}>
                  <td style={{ padding: 7, color: '#6e7681' }}>{t.id}</td>
                  <td>{t.host}</td>
                  <td style={{ color: '#8b949e' }}>{t.method}</td>
                  <td style={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {t.path}
                  </td>
                  <td style={{ color: statusColor(t.status_code || 0) }}>{t.status_code || '—'}</td>
                  <td>{t.finding_id ? `#${t.finding_id}` : ''}</td>
                </tr>
              ))}
              {!items.length && (
                <tr><td colSpan={6} style={{ padding: 14, color: '#6e7681' }}>
                  Chưa có traffic. Bật capture, rồi chạy workflow — HTTP của tool đi qua proxy bị ghi lại làm evidence.
                </td></tr>
              )}
            </tbody>
          </table>
        </div>

        <div style={{ border: '1px solid #232a3a', borderRadius: 8, padding: 12, maxHeight: '70vh', overflowY: 'auto' }}>
          {!detail && <div style={{ color: '#6e7681', fontSize: 12 }}>Chọn một bản ghi để xem request/response.</div>}
          {detail && (
            <>
              <div style={{ fontSize: 12, marginBottom: 8 }}>
                <b>{detail.method}</b> {detail.host}{detail.path} ·
                <span style={{ color: statusColor(detail.status_code || 0) }}> {detail.status_code}</span>
              </div>
              <div style={{ fontSize: 11, color: '#7ee2a8', marginBottom: 4 }}>── REQUEST ──</div>
              <pre style={{ margin: 0, whiteSpace: 'pre-wrap', fontSize: 11, color: '#c9d1d9' }}>{detail.request}</pre>
              <div style={{ fontSize: 11, color: '#7ee2a8', margin: '10px 0 4px' }}>── RESPONSE ──</div>
              <pre style={{ margin: 0, whiteSpace: 'pre-wrap', fontSize: 11, color: '#c9d1d9' }}>{detail.response}</pre>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
