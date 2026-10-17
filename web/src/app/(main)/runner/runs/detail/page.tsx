"use client";

import * as React from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  ArrowLeftIcon,
  BanIcon,
  CopyIcon,
  DownloadIcon,
  ExternalLinkIcon,
  FileIcon,
  PauseIcon,
  PlayIcon,
  RefreshCwIcon,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { k1z } from "@/lib/k1z";

const API = "/api/v1";
const TABS = ["Logs", "Findings", "Screenshots", "Files", "Report"] as const;
type Tab = (typeof TABS)[number];
const TERMINAL = ["completed", "failed", "cancelled", "paused", "not_found"];

const SEV_COLOR: Record<string, string> = {
  critical: "#f85149",
  high: "#f0883e",
  medium: "#f0b429",
  low: "#58a6ff",
  info: "#9aa7b8",
  unknown: "#5c6773",
};

interface Step {
  id: string;
  status: string;
  name?: string;
  cmd?: string;
  duration_ms?: number;
}
interface Run {
  id: string;
  target: string;
  workflow: string;
  status: string;
  findings_count?: number;
  started_at?: string;
  created_at?: string;
  finished_at?: string;
  returncode?: number | null;
  total_logs?: number;
  steps?: Step[];
}
interface Finding {
  id: number | string;
  kind: string;
  severity?: string;
  status: string;
  name?: string;
  host?: string;
  url?: string;
  ip?: string;
  port?: number;
  protocol?: string;
  title?: string;
  tech?: string[];
  template_id?: string;
  description?: string;
  evidence?: string;
}
interface Shot {
  file: string;
  name: string;
  url?: string | null;
  title?: string | null;
  status?: number | null;
  size: number;
}
interface FileNode {
  path: string;
  name: string;
  size: number;
  ext: string;
}

const KIND_LABEL: Record<string, string> = {
  vuln: "Vulnerability",
  port: "Port",
  http: "HTTP",
  subdomain: "Subdomain",
  url: "URL",
  secret: "Secret",
  param: "Param",
  endpoint: "Endpoint",
};

function fmtDate(iso?: string): string {
  if (!iso) return "—";
  return iso.slice(0, 16).replace("T", " ");
}
function durSecs(run: Run): number | null {
  if (run.finished_at && run.started_at)
    return Math.round((new Date(run.finished_at).getTime() - new Date(run.started_at).getTime()) / 1000);
  return null;
}
function formatDuration(seconds: number | null): string {
  if (seconds == null || isNaN(seconds)) return "—";
  const s = Math.round(seconds);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rs = s % 60;
  if (m < 60) return rs ? `${m}m ${rs}s` : `${m}m`;
  const h = Math.floor(m / 60);
  const rm = m % 60;
  return rm ? `${h}h ${rm}m` : `${h}h`;
}
function fmtSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
}
function wsToken(): string {
  try {
    return localStorage.getItem("artex_token") ?? "";
  } catch {
    return "";
  }
}

const STATUS_COLOR: Record<string, string> = {
  running: "text-blue-600",
  completed: "text-green-600",
  failed: "text-red-600",
  queued: "text-neutral-500",
  paused: "text-amber-600",
  cancelled: "text-neutral-500",
};

// ── Step progress ──────────────────────────────────────────────────────────
function StepProgress({ steps, running }: { steps: Step[]; running: boolean }) {
  const [selected, setSelected] = React.useState<string | null>(null);
  if (!steps || steps.length === 0) return null;

  const done = steps.filter((s) => s.status === "ok").length;
  const failed = steps.filter((s) => s.status === "failed").length;
  const skipped = steps.filter((s) => s.status === "skipped").length;
  const total = steps.length;
  const pct = Math.round((done / total) * 100);
  const selectedStep = steps.find((s) => s.id === selected) ?? null;
  const barColor = failed > 0 ? "#f85149" : "#3fb950";

  return (
    <div className="border-border border-b px-6 py-3">
      <div className="mb-2.5 flex flex-wrap items-center gap-3">
        <span className="text-muted-foreground text-xs tabular-nums">
          {done}/{total} steps
        </span>
        {skipped > 0 && <span className="text-muted-foreground text-[10px]">{skipped} skipped</span>}
        {failed > 0 && <span className="text-xs text-red-500">{failed} failed</span>}
        {!running && failed === 0 && done === total - skipped && done > 0 && (
          <span className="text-xs text-green-600">✓ Complete</span>
        )}
        <div className="bg-muted ml-2 h-1.5 flex-1 overflow-hidden rounded-full">
          <div className="h-full rounded-full transition-all duration-500" style={{ width: `${pct}%`, background: barColor }} />
        </div>
        <span className="text-muted-foreground text-[10px] tabular-nums">{pct}%</span>
      </div>

      {selectedStep && (
        <div className="bg-muted/40 border-border mb-2.5 rounded-md border px-2.5 py-1.5">
          <p className="mb-1 text-[10px] font-semibold">
            {selectedStep.name || selectedStep.id.replace(/_/g, " ")}
            <span className="text-muted-foreground ml-2 text-[9px] font-mono uppercase">{selectedStep.status}</span>
          </p>
          <pre className="text-muted-foreground font-mono text-[10px] leading-snug break-all whitespace-pre-wrap">
            {selectedStep.cmd || "no command recorded"}
          </pre>
        </div>
      )}

      <div className="flex flex-wrap gap-1.5">
        {steps.map((step) => {
          const dur = step.duration_ms != null ? formatDuration(Math.round(step.duration_ms / 1000)) : null;
          const isSel = selected === step.id;
          const icon =
            step.status === "ok"
              ? "✓"
              : step.status === "failed"
                ? "✗"
                : step.status === "running"
                  ? "◉"
                  : step.status === "paused"
                    ? "⏸"
                    : step.status === "skipped"
                      ? "–"
                      : "○";
          return (
            <button
              key={step.id}
              onClick={() => setSelected(isSel ? null : step.id)}
              title={`${step.id} · ${step.status}${dur ? ` · ${dur}` : ""}`}
              className={`flex items-center gap-1 rounded border px-2 py-0.5 text-[10px] transition-colors ${
                isSel ? "border-primary bg-primary/10" : "border-border hover:border-primary/40"
              }`}
            >
              <span
                className={`font-mono text-[11px] ${
                  step.status === "ok"
                    ? "text-green-600"
                    : step.status === "failed"
                      ? "text-red-500"
                      : step.status === "running"
                        ? "animate-pulse text-blue-600"
                        : "text-muted-foreground"
                }`}
              >
                {icon}
              </span>
              <span className="text-muted-foreground">{step.id.replace(/_/g, " ")}</span>
              {dur && step.status === "ok" && <span className="text-muted-foreground/60 ml-0.5">{dur}</span>}
            </button>
          );
        })}
      </div>
    </div>
  );
}

// ── Logs tab ─────────────────────────────────────────────────────────────────
function LogsTab({ logs, running }: { logs: string[]; running: boolean }) {
  const ref = React.useRef<HTMLPreElement>(null);
  React.useEffect(() => {
    if (running && ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [logs, running]);
  return (
    <pre
      ref={ref}
      className="h-full overflow-auto bg-[#0d1117] p-4 font-mono text-xs leading-relaxed whitespace-pre-wrap text-[#e6edf3]"
    >
      {logs.length ? logs.join("\n") : running ? "Connecting…" : "No logs."}
    </pre>
  );
}

// ── Findings tab ───────────────────────────────────────────────────────────
function FindingsTab({ runId }: { runId: string }) {
  const [items, setItems] = React.useState<Finding[]>([]);
  const [total, setTotal] = React.useState<number | null>(null);
  const [status, setStatus] = React.useState("open");
  const [expanded, setExpanded] = React.useState<string | number | null>(null);
  const [loading, setLoading] = React.useState(true);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const q = status ? `?limit=500&status=${status}` : "?limit=500";
      const res = (await k1z.get(`/runs/${runId}/findings${q}`)) as { total?: number; items?: Finding[] };
      setItems(res.items ?? []);
      setTotal(res.total ?? (res.items?.length ?? 0));
    } catch {
      setItems([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [runId, status]);
  React.useEffect(() => {
    load();
  }, [load]);

  async function changeStatus(id: string | number, s: string) {
    await k1z.patch(`/findings/${id}`, { status: s });
    setItems((prev) => prev.map((f) => (f.id === id ? { ...f, status: s } : f)));
  }

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-border flex flex-shrink-0 flex-wrap items-center gap-2 border-b px-4 py-2">
        <select
          className="border-input bg-background h-8 rounded-md border px-2 text-xs"
          value={status}
          onChange={(e) => setStatus(e.target.value)}
        >
          <option value="">All statuses</option>
          <option value="open">Open</option>
          <option value="fp">False positive</option>
          <option value="resolved">Resolved</option>
        </select>
        <span className="text-muted-foreground ml-auto text-xs">{total ?? "—"} findings</span>
        <Button size="sm" variant="outline" onClick={() => k1z.post(`/runs/${runId}/findings/reparse`).then(load)}>
          <RefreshCwIcon className="size-3.5" /> Reparse
        </Button>
      </div>
      <div className="flex-1 overflow-y-auto">
        {loading && <div className="text-muted-foreground animate-pulse p-8 text-center text-xs">Loading findings…</div>}
        {!loading && items.length === 0 && (
          <div className="text-muted-foreground p-8 text-center text-xs">No findings.</div>
        )}
        {!loading &&
          items.map((f) => (
            <div
              key={f.id}
              className="border-border hover:bg-muted/50 cursor-pointer border-b transition-colors"
              onClick={() => setExpanded(expanded === f.id ? null : f.id)}
            >
              <div className="flex flex-wrap items-center gap-3 px-4 py-2.5">
                {f.kind === "vuln" && f.severity && (
                  <span
                    className="rounded-full border px-2 py-0.5 text-[10px] font-mono uppercase"
                    style={{
                      color: SEV_COLOR[f.severity] ?? SEV_COLOR.unknown,
                      borderColor: (SEV_COLOR[f.severity] ?? SEV_COLOR.unknown) + "4d",
                      background: (SEV_COLOR[f.severity] ?? SEV_COLOR.unknown) + "16",
                    }}
                  >
                    {f.severity}
                  </span>
                )}
                <span className="border-border text-muted-foreground rounded border px-1.5 py-0.5 text-[10px] font-mono whitespace-nowrap">
                  {KIND_LABEL[f.kind] || f.kind}
                </span>
                <span className="min-w-0 flex-1 truncate text-xs font-medium">{f.name || f.host}</span>
                <span className="text-muted-foreground hidden max-w-[200px] truncate font-mono text-[11px] md:block">
                  {f.host}
                </span>
                <select
                  value={f.status}
                  onClick={(e) => e.stopPropagation()}
                  onChange={(e) => {
                    e.stopPropagation();
                    changeStatus(f.id, e.target.value);
                  }}
                  className="border-input bg-background rounded border px-1.5 py-0.5 text-[10px] font-mono"
                >
                  <option value="open">OPEN</option>
                  <option value="fp">FALSE+</option>
                  <option value="resolved">RESOLVED</option>
                </select>
              </div>
              {expanded === f.id && (
                <div className="bg-muted/30 border-border space-y-1.5 border-t px-4 pt-2 pb-4 text-xs">
                  {f.template_id && (
                    <div>
                      <span className="text-muted-foreground">Template </span>
                      <span className="text-primary font-mono">{f.template_id}</span>
                    </div>
                  )}
                  {f.url && (
                    <div>
                      <span className="text-muted-foreground">URL </span>
                      <a
                        href={f.url}
                        target="_blank"
                        rel="noreferrer"
                        onClick={(e) => e.stopPropagation()}
                        className="text-primary font-mono break-all hover:underline"
                      >
                        {f.url}
                      </a>
                    </div>
                  )}
                  {f.ip && (
                    <div>
                      <span className="text-muted-foreground">IP </span>
                      <span className="font-mono">{f.ip}</span>
                    </div>
                  )}
                  {f.port && (
                    <div>
                      <span className="text-muted-foreground">Port </span>
                      <span className="font-mono">
                        {f.port}/{f.protocol || "tcp"}
                      </span>
                    </div>
                  )}
                  {f.title && (
                    <div>
                      <span className="text-muted-foreground">Title </span>
                      {f.title}
                    </div>
                  )}
                  {f.description && <p className="text-muted-foreground mt-1 leading-relaxed">{f.description}</p>}
                  {f.evidence && (
                    <pre className="bg-background border-border mt-2 max-h-48 overflow-x-auto rounded border p-3 text-[10px] break-all whitespace-pre-wrap">
                      {f.evidence}
                    </pre>
                  )}
                </div>
              )}
            </div>
          ))}
      </div>
    </div>
  );
}

// ── Screenshots tab ──────────────────────────────────────────────────────────
function ScreenshotsTab({ runId }: { runId: string }) {
  const [shots, setShots] = React.useState<Shot[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [lightbox, setLightbox] = React.useState<Shot | null>(null);

  React.useEffect(() => {
    k1z
      .get(`/runs/${runId}/screenshots`)
      .then((r) => setShots((r as Shot[]) ?? []))
      .catch(() => setShots([]))
      .finally(() => setLoading(false));
  }, [runId]);

  const imgUrl = (file: string) => `${API}/runs/${runId}/files/${file}`;

  if (loading) return <div className="text-muted-foreground p-8 text-center text-sm">Loading screenshots…</div>;
  if (!shots.length) return <div className="text-muted-foreground p-8 text-center text-sm">No screenshots captured.</div>;

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))" }}>
        {shots.map((s) => (
          <button
            key={s.file}
            onClick={() => setLightbox(s)}
            className="border-border bg-card hover:border-primary group overflow-hidden rounded-lg border text-left transition-colors"
          >
            <div className="bg-muted h-40 overflow-hidden">
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src={imgUrl(s.file)}
                alt={s.url || s.name}
                loading="lazy"
                className="size-full object-cover object-top transition-transform duration-300 group-hover:scale-105"
              />
            </div>
            <div className="space-y-0.5 px-3 py-2">
              {s.title && <p className="truncate text-[11px] font-medium">{s.title}</p>}
              <p className="text-muted-foreground truncate font-mono text-[10px]">{s.url || s.name}</p>
              <p className="text-muted-foreground/70 text-[9px]">{(s.size / 1024).toFixed(0)} KB</p>
            </div>
          </button>
        ))}
      </div>
      {lightbox && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-sm"
          onClick={() => setLightbox(null)}
        >
          <div
            className="border-border bg-card max-h-full w-full max-w-5xl overflow-auto rounded-xl border shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="border-border flex items-center gap-3 border-b px-4 py-3">
              <p className="text-muted-foreground min-w-0 flex-1 truncate font-mono text-xs">
                {lightbox.url || lightbox.name}
              </p>
              <a
                href={imgUrl(lightbox.file)}
                target="_blank"
                rel="noreferrer"
                className="text-muted-foreground hover:text-foreground border-border rounded border px-2 py-1 text-xs"
              >
                ↗ Full size
              </a>
              <button onClick={() => setLightbox(null)} className="text-muted-foreground hover:text-foreground px-2 text-sm">
                ✕
              </button>
            </div>
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src={imgUrl(lightbox.file)} alt={lightbox.url || lightbox.name} className="block w-full" />
          </div>
        </div>
      )}
    </div>
  );
}

// ── Files tab ──────────────────────────────────────────────────────────────
function FilesTab({ runId }: { runId: string }) {
  const [files, setFiles] = React.useState<FileNode[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [q, setQ] = React.useState("");

  React.useEffect(() => {
    k1z
      .get(`/runs/${runId}/files`)
      .then((r) => setFiles((r as FileNode[]) ?? []))
      .catch(() => setFiles([]))
      .finally(() => setLoading(false));
  }, [runId]);

  const fileUrl = (path: string) => `${API}/runs/${runId}/files/${path.split("/").map(encodeURIComponent).join("/")}`;
  const filtered = q ? files.filter((f) => f.path.toLowerCase().includes(q.toLowerCase())) : files;

  if (loading) return <div className="text-muted-foreground p-8 text-center text-sm">Loading files…</div>;
  if (!files.length) return <div className="text-muted-foreground p-8 text-center text-sm">No files.</div>;

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-border flex flex-shrink-0 items-center gap-3 border-b px-4 py-2">
        <span className="text-muted-foreground text-xs tabular-nums">
          {filtered.length} / {files.length} files
        </span>
        <Input className="ml-auto h-8 w-64" placeholder="Filter by path…" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      <div className="divide-border flex-1 divide-y overflow-y-auto">
        {filtered.map((f) => (
          <a
            key={f.path}
            href={fileUrl(f.path)}
            target="_blank"
            rel="noreferrer"
            className="hover:bg-muted/50 flex items-center gap-2 px-4 py-2 transition-colors"
          >
            <FileIcon className="text-muted-foreground size-3.5 flex-shrink-0" />
            <span className="flex-1 truncate font-mono text-xs">{f.path}</span>
            <span className="text-muted-foreground flex-shrink-0 text-[10px]">{fmtSize(f.size)}</span>
            <DownloadIcon className="text-muted-foreground size-3.5 flex-shrink-0" />
          </a>
        ))}
      </div>
    </div>
  );
}

// ── Main ─────────────────────────────────────────────────────────────────────
function RunDetailInner() {
  const params = useSearchParams();
  const id = params.get("id") ?? "";
  const [run, setRun] = React.useState<Run | null>(null);
  const [tab, setTab] = React.useState<Tab>("Logs");
  const [logs, setLogs] = React.useState<string[]>([]);
  const [steps, setSteps] = React.useState<Step[]>([]);
  const statusRef = React.useRef<string | null>(null);

  React.useEffect(() => {
    statusRef.current = run?.status ?? null;
  }, [run?.status]);

  // initial run + log history
  React.useEffect(() => {
    if (!id) return;
    k1z
      .get(`/runs/${id}`)
      .then((r) => {
        const rr = r as Run;
        setRun(rr);
        setSteps(rr.steps ?? []);
        const total = rr.total_logs ?? 0;
        const offset = Math.max(0, total - 500);
        return k1z.get(`/runs/${id}/logs?offset=${offset}&limit=500`).then((res) => {
          const items = (res as { items?: string[] }).items ?? [];
          setLogs((prev) => (prev.length > 0 ? [...items, ...prev] : items));
        });
      })
      .catch(() => {});
  }, [id]);

  // live WS
  React.useEffect(() => {
    if (!id) return;
    const MAX_LIVE = 5000;
    let disposed = false;
    let ws: WebSocket | null = null;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let attempts = 0;

    function connect() {
      if (disposed || TERMINAL.includes(statusRef.current ?? "")) return;
      const proto = location.protocol === "https:" ? "wss" : "ws";
      const t = wsToken();
      ws = new WebSocket(`${proto}://${location.host}/ws/runs/${id}${t ? `?token=${encodeURIComponent(t)}` : ""}`);
      ws.onopen = () => {
        attempts = 0;
      };
      ws.onmessage = (e) => {
        let m: { type?: string; message?: string; status?: string; steps?: Step[]; total?: number };
        try {
          m = JSON.parse(e.data as string);
        } catch {
          return;
        }
        if (m.type === "log" && m.message != null) {
          setLogs((prev) => {
            const next = prev.length >= MAX_LIVE ? prev.slice(prev.length - MAX_LIVE + 1) : prev.slice();
            next.push(m.message!);
            return next;
          });
        } else if (m.type === "step" && m.steps) {
          setSteps(m.steps);
        } else if (m.type === "status" && m.status) {
          statusRef.current = m.status;
          setRun((prev) => (prev ? { ...prev, status: m.status! } : prev));
        } else if (m.type === "done") {
          statusRef.current = m.status ?? null;
          setRun((prev) => (prev ? { ...prev, status: m.status ?? prev.status } : prev));
          if (m.steps) setSteps(m.steps);
          try {
            ws?.close();
          } catch {
            /* noop */
          }
          k1z
            .get(`/runs/${id}`)
            .then((r) => {
              setRun(r as Run);
              setSteps((r as Run).steps ?? []);
            })
            .catch(() => {});
        }
      };
      ws.onclose = () => {
        if (disposed || TERMINAL.includes(statusRef.current ?? "")) return;
        const delay = Math.min(1000 * 2 ** attempts, 15000);
        attempts += 1;
        timer = setTimeout(connect, delay);
      };
      ws.onerror = () => {
        try {
          ws?.close();
        } catch {
          /* noop */
        }
      };
    }
    connect();
    return () => {
      disposed = true;
      if (timer) clearTimeout(timer);
      try {
        ws?.close();
      } catch {
        /* noop */
      }
    };
  }, [id]);

  if (!id) return <div className="text-muted-foreground p-8 text-sm">No run selected.</div>;
  if (!run) return <div className="text-muted-foreground p-8 text-sm">Loading…</div>;

  const isActive = run.status === "running";
  const isDone = ["completed", "failed", "cancelled", "paused"].includes(run.status);
  const canResume = ["paused", "failed"].includes(run.status);
  const dur = run.status === "running" ? "running…" : formatDuration(durSecs(run));

  return (
    <div className="flex h-[calc(100vh-var(--header-height,4rem))] min-h-0 flex-col">
      {/* Header */}
      <div className="border-border flex flex-wrap items-start justify-between gap-3 border-b px-6 py-4">
        <div>
          <div className="mb-1 flex items-center gap-2 text-xs">
            <Link href="/runner/runs" className="text-muted-foreground hover:text-primary flex items-center gap-1">
              <ArrowLeftIcon className="size-3" /> Runs
            </Link>
            <span className="text-border">/</span>
            <span className="font-mono">{id}</span>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="font-mono text-base font-bold">{run.target}</h1>
            <span className={`text-sm font-medium ${STATUS_COLOR[run.status] ?? ""}`}>{run.status}</span>
            <span className="text-muted-foreground text-xs">{run.workflow}</span>
            {(run.findings_count ?? 0) > 0 && (
              <span className="rounded border border-orange-500 px-1.5 py-0.5 font-mono text-xs text-orange-500">
                {run.findings_count} findings
              </span>
            )}
          </div>
          <div className="text-muted-foreground mt-1 flex flex-wrap gap-4 text-[11px]">
            <span>Started: {fmtDate(run.started_at || run.created_at)}</span>
            <span>
              Duration: <span className={run.status === "running" ? "text-green-600" : ""}>{dur}</span>
            </span>
            {run.returncode != null && run.returncode !== 0 && (
              <span className="text-red-500">Exit: {run.returncode}</span>
            )}
            <button
              className="hover:text-foreground flex items-center gap-1 font-mono transition-colors"
              onClick={() => navigator.clipboard.writeText(id)}
            >
              <CopyIcon className="size-3" /> copy id
            </button>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {isActive && (
            <>
              <Button size="sm" variant="outline" onClick={() => k1z.post(`/runs/${id}/pause`).catch(() => {})}>
                <PauseIcon className="size-3.5" /> Pause
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="text-red-500"
                onClick={() => k1z.post(`/runs/${id}/cancel`).then((r) => setRun(r as Run))}
              >
                <BanIcon className="size-3.5" /> Cancel
              </Button>
            </>
          )}
          {canResume && (
            <Button
              size="sm"
              variant="outline"
              className="text-green-600"
              onClick={() =>
                k1z.post(`/runs/${id}/resume`).then((r) => {
                  setRun(r as Run);
                  setSteps((r as Run).steps ?? []);
                  statusRef.current = "running";
                })
              }
            >
              <PlayIcon className="size-3.5" /> Resume
            </Button>
          )}
          {isDone && (
            <>
              <a href={`${API}/runs/${id}/report`} target="_blank" rel="noreferrer">
                <Button size="sm" variant="outline">
                  <ExternalLinkIcon className="size-3.5" /> Report
                </Button>
              </a>
              <a href={`${API}/runs/${id}/report-draft?format=hackerone`}>
                <Button size="sm" variant="outline">
                  <DownloadIcon className="size-3.5" /> Draft H1
                </Button>
              </a>
            </>
          )}
        </div>
      </div>

      <StepProgress steps={steps} running={isActive} />

      {/* Tabs */}
      <div className="border-border flex gap-0 border-b px-6">
        {TABS.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`flex items-center gap-1.5 border-b-2 px-4 py-2.5 text-xs transition-colors ${
              tab === t ? "border-primary text-primary" : "text-muted-foreground hover:text-foreground border-transparent"
            }`}
          >
            {t}
            {t === "Findings" && (run.findings_count ?? 0) > 0 && (
              <span className="rounded bg-orange-500/20 px-1 text-[9px] text-orange-500">{run.findings_count}</span>
            )}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-hidden">
        {tab === "Logs" && <LogsTab logs={logs} running={isActive} />}
        {tab === "Findings" && <FindingsTab runId={id} />}
        {tab === "Screenshots" && <ScreenshotsTab runId={id} />}
        {tab === "Files" && <FilesTab runId={id} />}
        {tab === "Report" && (
          <div className="space-y-4 p-6">
            {isDone ? (
              <>
                <p className="text-muted-foreground text-sm">
                  The report is generated on-the-fly from the structured findings — vulnerabilities, HTTP services, open
                  ports, and discovered subdomains.
                </p>
                <div className="flex gap-3">
                  <a href={`${API}/runs/${id}/report`} target="_blank" rel="noreferrer">
                    <Button variant="outline">
                      <ExternalLinkIcon className="size-4" /> Open HTML Report
                    </Button>
                  </a>
                  <a href={`${API}/runs/${id}/report-draft?format=bugcrowd`}>
                    <Button variant="outline">
                      <DownloadIcon className="size-4" /> Draft (Bugcrowd)
                    </Button>
                  </a>
                </div>
                <p className="text-muted-foreground text-xs">
                  The report opens in a new tab and can be saved as PDF via browser print (Ctrl+P → Save as PDF).
                </p>
              </>
            ) : (
              <p className="text-muted-foreground text-sm">Report is available after the run completes.</p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default function RunDetailPage() {
  return (
    <React.Suspense fallback={<div className="text-muted-foreground p-8 text-sm">Loading…</div>}>
      <RunDetailInner />
    </React.Suspense>
  );
}
