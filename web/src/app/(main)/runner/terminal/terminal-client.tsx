"use client";

import * as React from "react";
import { FitAddon } from "@xterm/addon-fit";
import { SerializeAddon } from "@xterm/addon-serialize";
import { Unicode11Addon } from "@xterm/addon-unicode11";
import { WebLinksAddon } from "@xterm/addon-web-links";
import { WebglAddon } from "@xterm/addon-webgl";
import { Terminal } from "@xterm/xterm";
import { PlusIcon, XIcon } from "lucide-react";

import "@xterm/xterm/css/xterm.css";

// Module-level session store survives React unmount/remount so switching tabs
// (or leaving and returning to the page) keeps each PTY session + its screen.
interface Session {
  id: string;
  label: string;
  snapshot: string;
}
const store: { sessions: Session[]; activeId: string | null; nextLabel: number } = {
  sessions: [],
  activeId: null,
  nextLabel: 1,
};

function genId(): string {
  return Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
}

function makeSession(): Session {
  return { id: genId(), label: String(store.nextLabel++), snapshot: "" };
}

function wsToken(): string {
  try {
    return localStorage.getItem("artex_token") ?? "";
  } catch {
    return "";
  }
}

function termWsUrl(sessionId: string): string {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const t = wsToken();
  return `${proto}://${location.host}/ws/terminal/${sessionId}${t ? `?token=${encodeURIComponent(t)}` : ""}`;
}

type Status = "connecting" | "connected" | "disconnected" | "error";
const STATUS_COLOR: Record<Status, string> = {
  connecting: "bg-yellow-400 animate-pulse",
  connected: "bg-green-500",
  disconnected: "bg-neutral-500",
  error: "bg-red-500",
};

const TERM_THEME = {
  background: "#0d1117",
  foreground: "#e6edf3",
  cursor: "#58a6ff",
  cursorAccent: "#0d1117",
  selectionBackground: "#264f7844",
  black: "#21262d",
  brightBlack: "#6e7681",
  red: "#ff7b72",
  brightRed: "#ffa198",
  green: "#3fb950",
  brightGreen: "#56d364",
  yellow: "#d29922",
  brightYellow: "#e3b341",
  blue: "#58a6ff",
  brightBlue: "#79c0ff",
  magenta: "#bc8cff",
  brightMagenta: "#d2a8ff",
  cyan: "#39c5cf",
  brightCyan: "#56d4dd",
  white: "#b1bac4",
  brightWhite: "#f0f6fc",
};

if (store.sessions.length === 0) {
  const s = makeSession();
  store.sessions = [s];
  store.activeId = s.id;
}

export default function TerminalClient() {
  const [sessions, setSessions] = React.useState<Session[]>(() => [...store.sessions]);
  const [activeId, setActiveId] = React.useState<string | null>(() => store.activeId);
  const [status, setStatus] = React.useState<Status>("disconnected");

  const containerRef = React.useRef<HTMLDivElement>(null);
  const termRef = React.useRef<Terminal | null>(null);
  const wsRef = React.useRef<WebSocket | null>(null);
  const roRef = React.useRef<ResizeObserver | null>(null);
  const serializeRef = React.useRef<SerializeAddon | null>(null);

  const connect = React.useCallback((session: Session) => {
    if (!containerRef.current) return;
    setStatus("connecting");

    const term = new Terminal({
      theme: TERM_THEME,
      fontFamily: '"Cascadia Code", "Fira Code", "JetBrains Mono", "Consolas", monospace',
      fontSize: 14,
      lineHeight: 1.45,
      cursorBlink: true,
      cursorStyle: "bar",
      scrollback: 10000,
      allowProposedApi: true,
    });

    const fit = new FitAddon();
    const serialize = new SerializeAddon();
    term.loadAddon(fit);
    term.loadAddon(serialize);
    term.loadAddon(new Unicode11Addon());
    term.loadAddon(new WebLinksAddon());
    term.open(containerRef.current);

    requestAnimationFrame(() => {
      fit.fit();
      try {
        const webgl = new WebglAddon();
        webgl.onContextLoss(() => webgl.dispose());
        term.loadAddon(webgl);
      } catch {
        /* webgl unavailable — canvas fallback */
      }
      term.unicode.activeVersion = "11";

      termRef.current = term;
      serializeRef.current = serialize;

      if (session.snapshot) term.write(session.snapshot);

      const ws = new WebSocket(termWsUrl(session.id));
      ws.binaryType = "arraybuffer";
      wsRef.current = ws;

      ws.onopen = () => {
        setStatus("connected");
        ws.send(JSON.stringify({ type: "resize", rows: term.rows, cols: term.cols }));
      };
      ws.onmessage = (e) =>
        term.write(e.data instanceof ArrayBuffer ? new Uint8Array(e.data) : (e.data as string));
      ws.onclose = () => setStatus("disconnected");
      ws.onerror = () => setStatus("error");

      term.onData((data) => {
        if (ws.readyState === WebSocket.OPEN) ws.send(new TextEncoder().encode(data));
      });

      const sendResize = () => {
        fit.fit();
        if (ws.readyState === WebSocket.OPEN)
          ws.send(JSON.stringify({ type: "resize", rows: term.rows, cols: term.cols }));
      };
      const ro = new ResizeObserver(sendResize);
      ro.observe(containerRef.current!);
      roRef.current = ro;
    });
  }, []);

  React.useEffect(() => {
    const sessionId = activeId;
    const session = store.sessions.find((s) => s.id === sessionId);
    if (session) connect(session);

    return () => {
      if (serializeRef.current) {
        const snap = serializeRef.current.serialize();
        const s = store.sessions.find((x) => x.id === sessionId);
        if (s) s.snapshot = snap;
      }
      roRef.current?.disconnect();
      wsRef.current?.close();
      termRef.current?.dispose();
      termRef.current = null;
      serializeRef.current = null;
      wsRef.current = null;
    };
  }, [activeId, connect]);

  const switchTo = React.useCallback(
    (id: string) => {
      if (id === activeId) return;
      store.activeId = id;
      setActiveId(id);
    },
    [activeId],
  );

  const newSession = React.useCallback(() => {
    const s = makeSession();
    store.sessions = [...store.sessions, s];
    store.activeId = s.id;
    setSessions([...store.sessions]);
    setActiveId(s.id);
  }, []);

  const closeSession = React.useCallback(
    (e: React.MouseEvent, id: string) => {
      e.stopPropagation();
      const idx = store.sessions.findIndex((s) => s.id === id);
      const isActive = id === activeId;

      if (store.sessions.length === 1) {
        const fresh = makeSession();
        store.sessions = [fresh];
        store.activeId = fresh.id;
        setSessions([...store.sessions]);
        setActiveId(fresh.id);
        return;
      }

      store.sessions = store.sessions.filter((s) => s.id !== id);
      if (isActive) {
        const neighbor = store.sessions[Math.max(0, idx - 1)];
        store.activeId = neighbor.id;
        setSessions([...store.sessions]);
        setActiveId(neighbor.id);
      } else {
        setSessions([...store.sessions]);
      }
    },
    [activeId],
  );

  return (
    <div className="flex h-[calc(100vh-var(--header-height,4rem))] min-h-0 flex-col bg-[#0d1117]">
      <div className="flex flex-shrink-0 items-center border-b border-[#30363d] bg-[#010409]">
        <div className="flex min-w-0 flex-1 items-end gap-px overflow-x-auto px-2 pt-1.5">
          {sessions.map((s) => {
            const isActive = s.id === activeId;
            return (
              <div
                key={s.id}
                onClick={() => switchTo(s.id)}
                className={`group flex cursor-pointer items-center gap-1.5 rounded-t px-3 py-1.5 text-xs whitespace-nowrap transition-colors select-none ${
                  isActive
                    ? "border border-b-0 border-[#30363d] bg-[#0d1117] text-[#e6edf3]"
                    : "border border-transparent bg-transparent text-[#8b949e] hover:bg-[#161b22] hover:text-[#c9d1d9]"
                }`}
              >
                <span className="font-mono">bash {s.label}</span>
                <button
                  onClick={(e) => closeSession(e, s.id)}
                  title="Close session"
                  className={`flex size-3.5 items-center justify-center rounded-sm transition-all hover:bg-red-500/20 hover:text-red-400 ${
                    isActive ? "opacity-40 hover:opacity-100" : "opacity-0 group-hover:opacity-40 hover:!opacity-100"
                  }`}
                >
                  <XIcon className="size-2.5" />
                </button>
              </div>
            );
          })}
          <button
            onClick={newSession}
            title="New session"
            className="mb-0.5 flex size-7 flex-shrink-0 items-center justify-center rounded text-[#8b949e] transition-colors hover:bg-[#21262d] hover:text-[#e6edf3]"
          >
            <PlusIcon className="size-4" />
          </button>
        </div>
        <div className="flex flex-shrink-0 items-center gap-1.5 px-4">
          <span className={`inline-block size-2 rounded-full ${STATUS_COLOR[status]}`} />
          <span className="font-mono text-[10px] text-[#8b949e]">{status}</span>
        </div>
      </div>
      <div ref={containerRef} className="min-h-0 flex-1 overflow-hidden" style={{ padding: "6px 4px 4px 8px" }} />
    </div>
  );
}
