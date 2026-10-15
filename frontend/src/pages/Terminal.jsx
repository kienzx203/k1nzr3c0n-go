import React, { useEffect, useRef, useState, useCallback } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { WebglAddon } from '@xterm/addon-webgl'
import { Unicode11Addon } from '@xterm/addon-unicode11'
import { WebLinksAddon } from '@xterm/addon-web-links'
import { SerializeAddon } from '@xterm/addon-serialize'
import '@xterm/xterm/css/xterm.css'

// ── Module-level store — survives React unmount/remount ───────────────────────
const _store = {
  sessions:   [],   // [{id, label, snapshot}]
  activeId:   null,
  nextLabel:  1,
}

function genId() {
  return Math.random().toString(36).slice(2, 10) + Date.now().toString(36)
}

function makeSession() {
  return { id: genId(), label: String(_store.nextLabel++), snapshot: '' }
}

function termWsUrl(sessionId) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  return `${proto}://${location.host}/ws/terminal/${sessionId}`
}

const STATUS_COLOR = {
  connecting:   'bg-yellow-400 animate-pulse',
  connected:    'bg-[#3fb950]',
  disconnected: 'bg-[#8b949e]',
  error:        'bg-[#ff7b72]',
}

const TERM_THEME = {
  background:          '#0d1117',
  foreground:          '#e6edf3',
  cursor:              '#58a6ff',
  cursorAccent:        '#0d1117',
  selectionBackground: '#264f7844',
  black:   '#21262d',  brightBlack:   '#6e7681',
  red:     '#ff7b72',  brightRed:     '#ffa198',
  green:   '#3fb950',  brightGreen:   '#56d364',
  yellow:  '#d29922',  brightYellow:  '#e3b341',
  blue:    '#58a6ff',  brightBlue:    '#79c0ff',
  magenta: '#bc8cff',  brightMagenta: '#d2a8ff',
  cyan:    '#39c5cf',  brightCyan:    '#56d4dd',
  white:   '#b1bac4',  brightWhite:   '#f0f6fc',
}

// ── Init store on first load ──────────────────────────────────────────────────
if (_store.sessions.length === 0) {
  const s = makeSession()
  _store.sessions = [s]
  _store.activeId = s.id
}

export default function TerminalPage() {
  const [sessions, setSessions]   = useState(() => [..._store.sessions])
  const [activeId, setActiveId]   = useState(() => _store.activeId)
  const [status,   setStatus]     = useState('disconnected')

  const containerRef  = useRef(null)
  const termRef       = useRef(null)
  const fitRef        = useRef(null)
  const wsRef         = useRef(null)
  const roRef         = useRef(null)
  const serializeRef  = useRef(null)

  // Connect to the given session object — assumes container is already empty
  const connect = useCallback((session) => {
    if (!containerRef.current) return
    setStatus('connecting')

    const term = new Terminal({
      theme:            TERM_THEME,
      fontFamily:       '"Cascadia Code", "Fira Code", "JetBrains Mono", "Consolas", monospace',
      fontSize:         14,
      lineHeight:       1.45,
      cursorBlink:      true,
      cursorStyle:      'bar',
      scrollback:       10000,
      allowProposedApi: true,
    })

    const fit      = new FitAddon()
    const serialize = new SerializeAddon()
    term.loadAddon(fit)
    term.loadAddon(serialize)
    term.loadAddon(new Unicode11Addon())
    term.loadAddon(new WebLinksAddon())
    term.open(containerRef.current)

    requestAnimationFrame(() => {
      fit.fit()
      try {
        const webgl = new WebglAddon()
        webgl.onContextLoss(() => webgl.dispose())
        term.loadAddon(webgl)
      } catch (_) {}
      term.unicode.activeVersion = '11'

      termRef.current      = term
      fitRef.current       = fit
      serializeRef.current = serialize

      // Restore previous screen for this session
      if (session.snapshot) term.write(session.snapshot)

      const ws = new WebSocket(termWsUrl(session.id))
      ws.binaryType = 'arraybuffer'
      wsRef.current = ws

      ws.onopen    = () => {
        setStatus('connected')
        ws.send(JSON.stringify({ type: 'resize', rows: term.rows, cols: term.cols }))
      }
      ws.onmessage = (e) => term.write(e.data instanceof ArrayBuffer ? new Uint8Array(e.data) : e.data)
      ws.onclose   = () => setStatus('disconnected')
      ws.onerror   = () => setStatus('error')

      term.onData(data => {
        if (ws.readyState === WebSocket.OPEN) ws.send(new TextEncoder().encode(data))
      })

      const sendResize = () => {
        fit.fit()
        if (ws.readyState === WebSocket.OPEN)
          ws.send(JSON.stringify({ type: 'resize', rows: term.rows, cols: term.cols }))
      }
      const ro = new ResizeObserver(sendResize)
      ro.observe(containerRef.current)
      roRef.current = ro
    })
  }, [])

  // Re-mount terminal whenever activeId changes
  useEffect(() => {
    const sessionId = activeId  // capture for cleanup closure
    const session   = _store.sessions.find(s => s.id === sessionId)
    if (session) connect(session)

    return () => {
      // Snapshot screen before destroying
      if (serializeRef.current) {
        const snap = serializeRef.current.serialize()
        const s = _store.sessions.find(s => s.id === sessionId)
        if (s) s.snapshot = snap
      }
      roRef.current?.disconnect()
      wsRef.current?.close()
      termRef.current?.dispose()
      termRef.current      = null
      fitRef.current       = null
      serializeRef.current = null
      wsRef.current        = null
    }
  }, [activeId]) // eslint-disable-line react-hooks/exhaustive-deps

  // ── Tab actions ──────────────────────────────────────────────────────────────

  const switchTo = useCallback((id) => {
    if (id === activeId) return
    _store.activeId = id
    setActiveId(id)
  }, [activeId])

  const handleNewSession = useCallback(() => {
    const s = makeSession()
    _store.sessions = [..._store.sessions, s]
    setSessions([..._store.sessions])
    _store.activeId = s.id
    setActiveId(s.id)
  }, [])

  const handleClose = useCallback((e, id) => {
    e.stopPropagation()

    const idx  = _store.sessions.findIndex(s => s.id === id)
    const isActive = id === activeId

    if (_store.sessions.length === 1) {
      // Last session — reset instead of removing
      const fresh = makeSession()
      _store.sessions = [fresh]
      _store.activeId = fresh.id
      setSessions([..._store.sessions])
      setActiveId(fresh.id)
      return
    }

    _store.sessions = _store.sessions.filter(s => s.id !== id)

    if (isActive) {
      const neighbor = _store.sessions[Math.max(0, idx - 1)]
      _store.activeId = neighbor.id
      setSessions([..._store.sessions])
      setActiveId(neighbor.id)
    } else {
      setSessions([..._store.sessions])
    }
  }, [activeId])

  // ── Render ───────────────────────────────────────────────────────────────────
  return (
    <div className="flex flex-col h-full bg-[#0d1117]" style={{ minHeight: 0 }}>

      {/* ── Tab bar ── */}
      <div className="flex items-center border-b border-[#30363d] flex-shrink-0 bg-[#010409]">

        {/* Tabs */}
        <div className="flex items-end gap-px px-2 pt-1.5 flex-1 overflow-x-auto min-w-0">
          {sessions.map(s => {
            const isActive = s.id === activeId
            return (
              <div
                key={s.id}
                onClick={() => switchTo(s.id)}
                className={`
                  group flex items-center gap-1.5 px-3 py-1.5 rounded-t text-xs cursor-pointer select-none
                  transition-colors whitespace-nowrap
                  ${isActive
                    ? 'bg-[#0d1117] border border-b-0 border-[#30363d] text-[#e6edf3]'
                    : 'bg-transparent border border-transparent text-[#8b949e] hover:text-[#c9d1d9] hover:bg-[#161b22]'
                  }
                `}
              >
                {/* Terminal icon */}
                <svg width="11" height="11" viewBox="0 0 16 16" fill="currentColor" className={isActive ? 'text-[#58a6ff]' : 'text-[#6e7681]'}>
                  <path d="M0 2.75C0 1.784.784 1 1.75 1h12.5c.966 0 1.75.784 1.75 1.75v10.5A1.75 1.75 0 0 1 14.25 15H1.75A1.75 1.75 0 0 1 0 13.25Zm1.75-.25a.25.25 0 0 0-.25.25v10.5c0 .138.112.25.25.25h12.5a.25.25 0 0 0 .25-.25V2.75a.25.25 0 0 0-.25-.25ZM7.25 8a.75.75 0 0 1-.22.53l-2.25 2.25a.749.749 0 0 1-1.275-.326.749.749 0 0 1 .215-.734L5.44 8 3.72 6.28a.749.749 0 0 1 .326-1.275.749.749 0 0 1 .734.215l2.25 2.25c.141.14.22.331.22.53Zm1.5 1.5h3a.75.75 0 0 1 0 1.5h-3a.75.75 0 0 1 0-1.5Z"/>
                </svg>

                <span className="font-mono">bash {s.label}</span>

                {/* Close button */}
                <button
                  onClick={(e) => handleClose(e, s.id)}
                  title="Close session"
                  className={`
                    flex items-center justify-center w-3.5 h-3.5 rounded-sm
                    transition-all text-[10px] leading-none
                    ${isActive
                      ? 'opacity-40 hover:opacity-100 hover:bg-[#ff7b7222] hover:text-[#ff7b72]'
                      : 'opacity-0 group-hover:opacity-40 hover:!opacity-100 hover:bg-[#ff7b7222] hover:text-[#ff7b72]'
                    }
                  `}
                >
                  ✕
                </button>
              </div>
            )
          })}

          {/* + new session button inline with tabs */}
          <button
            onClick={handleNewSession}
            title="New session"
            className="flex items-center justify-center w-7 h-7 mb-0.5 rounded text-[#8b949e] hover:text-[#e6edf3] hover:bg-[#21262d] transition-colors flex-shrink-0 text-base leading-none"
          >
            +
          </button>
        </div>

        {/* Status indicator */}
        <div className="flex items-center gap-1.5 px-4 flex-shrink-0">
          <span className={`inline-block w-2 h-2 rounded-full ${STATUS_COLOR[status] || 'bg-gray-500'}`} />
          <span className="text-[10px] text-[#8b949e] font-mono">{status}</span>
        </div>
      </div>

      {/* ── Terminal canvas ── */}
      <div
        ref={containerRef}
        className="flex-1 overflow-hidden"
        style={{ minHeight: 0, padding: '6px 4px 4px 8px' }}
      />
    </div>
  )
}
