import React from 'react'
import { Routes, Route, NavLink, Navigate } from 'react-router-dom'
import Dashboard from './pages/Dashboard.jsx'
import Runs from './pages/Runs.jsx'
import RunDetail from './pages/RunDetail.jsx'
import Findings from './pages/Findings.jsx'
import Inventory from './pages/Inventory.jsx'
import Terminal from './pages/Terminal.jsx'
import Keys from './pages/Keys.jsx'
import Tools from './pages/Tools.jsx'
import Workflows from './pages/Workflows.jsx'
import WorkflowEditor from './pages/WorkflowEditor.jsx'
import Upload from './pages/Upload.jsx'
import Schedules from './pages/Schedules.jsx'
import Targets from './pages/Targets.jsx'
import Agent from './pages/Agent.jsx'
import AssetGraph from './pages/AssetGraph.jsx'
import Traffic from './pages/Traffic.jsx'
import Tasks from './pages/sys/Tasks.jsx'
import LLMRecordings from './pages/sys/LLMRecordings.jsx'
import Workspace from './pages/sys/Workspace.jsx'
import AssetSync from './pages/sys/AssetSync.jsx'
import SysLLM from './pages/sys/SysLLM.jsx'
import SysAgents from './pages/sys/SysAgents.jsx'
import SysMCP from './pages/sys/SysMCP.jsx'
import SysSkills from './pages/sys/SysSkills.jsx'
import SysNotifications from './pages/sys/SysNotifications.jsx'
import SysIntercept from './pages/sys/SysIntercept.jsx'
import SysAssetBlocking from './pages/sys/SysAssetBlocking.jsx'
import SysApprovals from './pages/sys/SysApprovals.jsx'
import SysToolExec from './pages/sys/SysToolExec.jsx'
import SysLogs from './pages/sys/SysLogs.jsx'
import SysSettings from './pages/sys/SysSettings.jsx'
import CommandPalette from './components/CommandPalette.jsx'
import { getTheme, applyTheme } from './theme.js'
import { api } from './api.js'

/* ── Inline icon set (16px, stroke) ───────────────────────────────────────── */
const I = {
  grid:     <path d="M3 3h4v4H3zM9.5 3h4v4h-4zM3 9.5h4v4H3zM9.5 9.5h4v4h-4z" />,
  radar:    <><circle cx="8" cy="8" r="6" /><circle cx="8" cy="8" r="2.5" /><path d="M8 2v2.5M8 11.5V14M2 8h2.5M11.5 8H14" /></>,
  flow:     <><circle cx="3.5" cy="4" r="1.8" /><circle cx="12.5" cy="4" r="1.8" /><circle cx="8" cy="12" r="1.8" /><path d="M3.5 5.8v1.7a2 2 0 0 0 2 2h5a2 2 0 0 0 2-2V5.8M8 9.5v.7" /></>,
  flag:     <path d="M3.5 1.5v13M3.5 2.5h8.5l-2 3 2 3H3.5" />,
  boxes:    <><path d="M2 5.5 8 2l6 3.5M2 5.5v6L8 15l6-3.5v-6M2 5.5 8 9m0 0 6-3.5M8 9v6" /></>,
  upload:   <path d="M8 10V2.5M5 5 8 2l3 3M2.5 10.5v2a1.5 1.5 0 0 0 1.5 1.5h8a1.5 1.5 0 0 0 1.5-1.5v-2" />,
  terminal: <><rect x="1.5" y="2.5" width="13" height="11" rx="1.5" /><path d="M4.5 6 7 8l-2.5 2M8.5 10.5H12" /></>,
  key:      <><circle cx="5" cy="10" r="3" /><path d="M7.2 7.8 13 2M10.5 4.5 13 7M12 3l1.8 1.8" /></>,
  wrench:   <path d="M13.5 4.5a3.5 3.5 0 0 1-4.8 4L4 13.2a1.4 1.4 0 0 1-2-2l4.7-4.7a3.5 3.5 0 0 1 4-4.8L8.5 4l.7 2.8L12 7.5z" />,
  spark:    <path d="M8 1.5 9.5 6.5 14.5 8 9.5 9.5 8 14.5 6.5 9.5 1.5 8 6.5 6.5z" />,
  target:   <><circle cx="8" cy="8" r="6" /><circle cx="8" cy="8" r="3.2" /><circle cx="8" cy="8" r="0.8" fill="currentColor" /></>,
  clock:    <><circle cx="8" cy="8" r="6" /><path d="M8 4.5V8l2.5 1.8" /></>,
  globe:    <><circle cx="8" cy="8" r="6" /><path d="M2 8h12M8 2c2 2 2 10 0 12M8 2c-2 2-2 10 0 12" /></>,
  bell:     <path d="M4 7a4 4 0 0 1 8 0c0 3 1 4 1 4H3s1-1 1-4M6.5 13.5a1.5 1.5 0 0 0 3 0" />,
  shield:   <path d="M8 1.5 13 3.5v4c0 3.5-2.2 5.8-5 7-2.8-1.2-5-3.5-5-7v-4z" />,
  list:     <path d="M5 4h9M5 8h9M5 12h9M2 4h.01M2 8h.01M2 12h.01" />,
  cog:      <><circle cx="8" cy="8" r="2.4" /><path d="M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.4 3.4l1.4 1.4M11.2 11.2l1.4 1.4M12.6 3.4l-1.4 1.4M4.8 11.2l-1.4 1.4" /></>,
  sun:      <><circle cx="8" cy="8" r="3.2" /><path d="M8 1v1.8M8 13.2V15M1 8h1.8M13.2 8H15M3 3l1.3 1.3M11.7 11.7 13 13M13 3l-1.3 1.3M4.3 11.7 3 13" /></>,
  moon:     <path d="M13.5 9.5A5.5 5.5 0 0 1 6.5 2.5a5.5 5.5 0 1 0 7 7z" />,
}
function Icon({ d, size = 15 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none"
         stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round"
         aria-hidden="true" style={{ flexShrink: 0 }}>
      {d}
    </svg>
  )
}

/* ── Brand mark ────────────────────────────────────────────────────────────── */
function Logo() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <defs>
        <linearGradient id="brand" x1="0" y1="0" x2="24" y2="24" gradientUnits="userSpaceOnUse">
          <stop stopColor="var(--accent)" />
          <stop offset="1" stopColor="var(--accent-2)" />
        </linearGradient>
      </defs>
      <path d="M12 1.5 21 6.75v10.5L12 22.5 3 17.25V6.75z"
            stroke="url(#brand)" strokeWidth="1.5" fill="rgba(91,155,255,.08)" />
      <circle cx="12" cy="12" r="4.2" stroke="url(#brand)" strokeWidth="1.3" opacity=".9" />
      <circle cx="12" cy="12" r="1.5" fill="url(#brand)" />
      <path d="M12 5.5v2.2M12 16.3v2.2M5.5 12h2.2M16.3 12h2.2"
            stroke="url(#brand)" strokeWidth="1.1" opacity=".6" />
    </svg>
  )
}

const NAV_GROUPS = [
  {
    title: 'Overview',
    items: [{ to: '/', label: 'Dashboard', icon: I.grid, exact: true }],
  },
  {
    title: 'Operations',
    items: [
      { to: '/agent',     label: 'AI Agent',   icon: I.spark },
      { to: '/tasks',     label: 'Tasks',      icon: I.radar },
      { to: '/runs',      label: 'Runs',       icon: I.flow },
      { to: '/workflows', label: 'Workflows',  icon: I.flow },
      { to: '/findings',  label: 'Findings',   icon: I.flag },
      { to: '/graph',     label: 'Asset Graph',icon: I.boxes },
      { to: '/inventory', label: 'Inventory',  icon: I.boxes },
      { to: '/traffic',   label: 'Traffic',    icon: I.globe },
      { to: '/targets',   label: 'Targets',    icon: I.target },
      { to: '/schedules', label: 'Schedules',  icon: I.clock },
    ],
  },
  {
    title: 'Intelligence',
    items: [
      { to: '/llm-records', label: 'LLM Recordings', icon: I.key },
      { to: '/asset-sync',  label: 'Asset Sync',     icon: I.boxes },
      { to: '/workspace',   label: 'Workspace',      icon: I.upload },
    ],
  },
  {
    title: 'System',
    items: [
      { to: '/sys/llm',       label: 'LLM Providers',   icon: I.spark },
      { to: '/sys/agents',    label: 'Agent Guard',     icon: I.target },
      { to: '/sys/mcp',       label: 'MCP Servers',     icon: I.wrench },
      { to: '/sys/skills',    label: 'Skills',          icon: I.key },
      { to: '/tools',         label: 'Tools',           icon: I.wrench },
      { to: '/sys/notify',    label: 'Notifications',   icon: I.bell },
      { to: '/sys/intercept', label: 'Intercept Rules', icon: I.shield },
      { to: '/sys/blocking',  label: 'Asset Blocking',  icon: I.shield },
      { to: '/sys/approvals', label: 'Approvals',       icon: I.flag },
      { to: '/sys/exec',      label: 'Tool Executions', icon: I.terminal },
      { to: '/sys/logs',      label: 'Logs',            icon: I.list },
      { to: '/sys/settings',  label: 'Settings',        icon: I.cog },
    ],
  },
]

export default function App() {
  const [version, setVersion] = React.useState('')
  React.useEffect(() => { api.systemVersion().then(v => setVersion(v.version || '')).catch(() => {}) }, [])
  const [theme, setTheme] = React.useState(getTheme())
  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark'
    applyTheme(next)
    setTheme(next)
  }

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: 'var(--bg)' }}>
      {/* ── Sidebar ─────────────────────────────────────────────────────── */}
      <aside className="w-[232px] flex-shrink-0 flex flex-col border-r" style={{ background: 'var(--bg-soft)', borderColor: 'var(--border)' }}>
        {/* Brand */}
        <div className="px-4 pt-4 pb-4 flex items-center gap-3 border-b" style={{ borderColor: 'var(--border)' }}>
          <Logo />
          <div className="min-w-0">
            <div className="font-extrabold tracking-[0.18em] text-[13px] leading-tight" style={{ color: 'var(--text)' }}>
              K1NZR3C0N
            </div>
            <div className="text-[9.5px] uppercase tracking-[0.16em] leading-tight mt-1" style={{ color: 'var(--text-3)' }}>
              Recon Console
            </div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto py-3 px-2.5 space-y-5">
          {NAV_GROUPS.map(group => (
            <div key={group.title}>
              <div className="px-2 mb-1.5 text-[9px] font-bold uppercase tracking-[0.16em]" style={{ color: 'var(--text-3)' }}>
                {group.title}
              </div>
              <div className="space-y-0.5">
                {group.items.map(({ to, label, icon, exact }) => (
                  <NavLink
                    key={to}
                    to={to}
                    end={exact}
                    className={({ isActive }) =>
                      'group relative flex items-center gap-2.5 px-2.5 py-[7px] rounded-md text-[12px] font-medium transition-colors ' +
                      (isActive ? 'nav-active' : 'nav-idle')
                    }
                  >
                    {({ isActive }) => (
                      <>
                        {isActive && (
                          <span className="absolute left-0 top-1.5 bottom-1.5 w-[3px] rounded-full" style={{ background: 'var(--accent)' }} />
                        )}
                        <Icon d={icon} />
                        {label}
                      </>
                    )}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>

        {/* Footer */}
        <div className="px-4 py-3 border-t flex items-center justify-between" style={{ borderColor: 'var(--border)' }}>
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full" style={{ background: 'var(--green)', boxShadow: '0 0 6px var(--green)' }} />
            <span className="text-[10px] font-mono" style={{ color: 'var(--text-3)' }}>{version ? `v${String(version).replace(/^v/, '')}` : ''}</span>
          </div>
          <button
            onClick={toggleTheme}
            className="p-1.5 rounded-md transition-colors hover:bg-[var(--surface-2)]"
            style={{ color: 'var(--text-2)' }}
            title={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
          >
            <Icon d={theme === 'dark' ? I.sun : I.moon} size={15} />
          </button>
        </div>
      </aside>

      {/* ── Main ────────────────────────────────────────────────────────── */}
      <main className="flex-1 overflow-y-auto" style={{ background: 'var(--bg)' }}>
        <Routes>
          <Route path="/"                      element={<Dashboard />} />
          <Route path="/agent"                 element={<Agent />} />
          <Route path="/graph"                 element={<AssetGraph />} />
          <Route path="/traffic"               element={<Traffic />} />
          <Route path="/tasks"                element={<Tasks />} />
          <Route path="/llm-records"          element={<LLMRecordings />} />
          <Route path="/asset-sync"           element={<AssetSync />} />
          <Route path="/workspace"            element={<Workspace />} />
          <Route path="/sys/llm"              element={<SysLLM />} />
          <Route path="/sys/agents"           element={<SysAgents />} />
          <Route path="/sys/mcp"              element={<SysMCP />} />
          <Route path="/sys/skills"           element={<SysSkills />} />
          <Route path="/sys/notify"           element={<SysNotifications />} />
          <Route path="/sys/intercept"        element={<SysIntercept />} />
          <Route path="/sys/blocking"         element={<SysAssetBlocking />} />
          <Route path="/sys/approvals"        element={<SysApprovals />} />
          <Route path="/sys/exec"             element={<SysToolExec />} />
          <Route path="/sys/logs"             element={<SysLogs />} />
          <Route path="/sys/settings"         element={<SysSettings />} />
          <Route path="/runs"                  element={<Runs />} />
          <Route path="/runs/:id"              element={<RunDetail />} />
          <Route path="/workflows"             element={<Workflows />} />
          <Route path="/workflows/:name"       element={<WorkflowEditor />} />
          <Route path="/findings"              element={<Findings />} />
          <Route path="/inventory"             element={<Inventory />} />
          <Route path="/targets"               element={<Targets />} />
          <Route path="/schedules"             element={<Schedules />} />
          <Route path="/upload"                element={<Upload />} />
          <Route path="/terminal"              element={<Terminal />} />
          <Route path="/keys"                  element={<Keys />} />
          <Route path="/tools"                 element={<Tools />} />
          <Route path="*"                      element={<Navigate to="/" replace />} />
        </Routes>
      </main>

      <CommandPalette />
    </div>
  )
}
