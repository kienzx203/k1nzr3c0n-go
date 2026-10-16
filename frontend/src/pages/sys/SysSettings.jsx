import React from 'react'
import { useEffect, useState } from 'react'
import { api } from '../../api.js'
import { PageHeader, Card, Table, Field, Badge } from '../../components/SysKit.jsx'


const IC = { d: <><circle cx="8" cy="8" r="2.2" /><path d="M8 1.8v2M8 12.2v2M1.8 8h2M12.2 8h2M3.6 3.6l1.4 1.4M11 11l1.4 1.4M12.4 3.6 11 5M5 11l-1.4 1.4" /></>, color: 'var(--text-2)' }
export default function SysSettings() {
  const [ver, setVer] = useState(null)
  const [upd, setUpd] = useState(null)
  const [msg, setMsg] = useState('')
  useEffect(() => { api.systemVersion().then(setVer).catch(() => {}); api.updateCheck().then(setUpd).catch(() => {}) }, [])
  return (
    <div className="fade-in p-6">
      <PageHeader icon={IC} title="System Settings" sub="Version, self-update, backup & data controls" />
      <div className="grid gap-4" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))' }}>
        <Card>
          <p className="text-[10px] uppercase tracking-wider font-semibold mb-2" style={{ color: 'var(--text-2)' }}>Version</p>
          <p className="font-mono text-[20px] font-bold" style={{ color: 'var(--accent)' }}>{ver?.version || '…'}</p>
          {upd?.update_available && (
            <button className="btn btn-primary mt-3 text-[11px]" onClick={async () => {
              try { await api.selfUpdate(); setMsg('Binary updated — run: systemctl restart k1nzr3c0n-go') } catch (e) { setMsg(e.message) } }}>
              ↑ Update to {upd.latest}
            </button>
          )}
          {msg && <p className="text-[11px] mt-2" style={{ color: 'var(--green)' }}>{msg}</p>}
        </Card>
        <Card>
          <p className="text-[10px] uppercase tracking-wider font-semibold mb-2" style={{ color: 'var(--text-2)' }}>Backup</p>
          <p className="text-[11px] mb-3" style={{ color: 'var(--text-3)' }}>DB snapshot + workflows + skills as tar.gz</p>
          <a className="btn btn-accent text-[11px]" href="/api/v1/system/backup" download>⬇ Download backup</a>
        </Card>
        <Card>
          <p className="text-[10px] uppercase tracking-wider font-semibold mb-2" style={{ color: 'var(--text-2)' }}>Language</p>
          <p className="text-[11px] mb-3" style={{ color: 'var(--text-3)' }}>Interface language is English (default). Toggle VI/EN next to the theme switch in the sidebar.</p>
        </Card>
      </div>
    </div>
  )
}
