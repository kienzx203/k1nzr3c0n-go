"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

function token(): string {
  try { return localStorage.getItem("artex_token") || ""; } catch { return ""; }
}

type Summary = { language?: string; engine?: string; functions?: number; edges?: number };
type Target = { name?: string; target?: string; summary?: Summary; findings?: unknown[]; error?: string };
type Result = { targets?: Target[]; summary?: Summary; findings?: unknown[]; name?: string };
type Source = { id: string; name: string; result: Result; ts: number };
// A shared-registry entry: a source uploaded here OR staged in a new-task draft (origin).
type RegEntry = { id: string; name: string; path: string; files: number; origin: "graph" | "task"; has_result: boolean };

const KEY = "sastk1nz.sources";
function loadSources(): Source[] {
  try { return JSON.parse(localStorage.getItem(KEY) || "[]"); } catch { return []; }
}
function saveSources(s: Source[]) {
  try { localStorage.setItem(KEY, JSON.stringify(s)); } catch { /* ignore */ }
}

export default function SastUploadPage() {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [sources, setSources] = useState<Source[]>(() => loadSources());
  const [registry, setRegistry] = useState<RegEntry[]>([]);
  const fileRef = useRef<HTMLInputElement>(null);
  const router = useRouter();

  // Load the SHARED source registry: sources uploaded here AND staged in new-task drafts.
  // This is what syncs the two upload paths — a source uploaded in New Task shows up here.
  function loadRegistry() {
    fetch("/api/sast/sources", { headers: { Authorization: `Bearer ${token()}` } })
      .then((r) => (r.ok ? r.json() : { sources: [] }))
      .then((d) => setRegistry((d.sources as RegEntry[]) || []))
      .catch(() => {});
  }
  useEffect(loadRegistry, []);

  // scanById runs the engine on an already-registered source (e.g. one uploaded in New Task)
  // and adds its call-graph result to the local list so it is viewable here.
  async function scanById(id: string, name: string) {
    setBusy(true); setErr("");
    try {
      const r = await fetch(`/api/sast/scan?id=${encodeURIComponent(id)}`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token()}` },
      });
      if (!r.ok) { const t = await r.text(); throw new Error(t || `HTTP ${r.status}`); }
      const j: Result = await r.json();
      const src: Source = { id: "s" + Date.now().toString(36), name, result: j, ts: Date.now() };
      const next = [...loadSources(), src];
      saveSources(next); setSources(next); loadRegistry();
    } catch (e) { setErr(e instanceof Error ? e.message : "scan failed"); }
    setBusy(false);
  }

  async function onFile(f?: File) {
    if (!f) return;
    if (!f.name.toLowerCase().endsWith(".zip")) { setErr("Please choose a .zip file."); return; }
    setBusy(true); setErr("");
    try {
      const nm = f.name.replace(/\.zip$/i, "");
      const r = await fetch(`/api/sast/scan?name=${encodeURIComponent(nm)}`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token()}`, "Content-Type": "application/zip" },
        body: f,
      });
      if (!r.ok) { const t = await r.text(); throw new Error(t || `HTTP ${r.status}`); }
      const j: Result = await r.json();
      const src: Source = { id: "s" + Date.now().toString(36), name: f.name.replace(/\.zip$/i, ""), result: j, ts: Date.now() };
      const next = [...loadSources(), src];
      saveSources(next); setSources(next); loadRegistry();
    } catch (e) { setErr(e instanceof Error ? e.message : "scan failed"); }
    setBusy(false);
  }

  function del(id: string) {
    const next = loadSources().filter((s) => s.id !== id);
    saveSources(next); setSources(next);
  }

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Source Review — Upload</h1>
        <p className="text-sm text-muted-foreground">Upload a .zip of source code. The SAST engine parses it (no execution) and builds a call graph. Each upload is kept as a separate source — view its graph in <b>Graph</b>.</p>
      </div>

      <Card className="p-8 flex flex-col items-center gap-4 border-dashed">
        <div className="text-lg font-medium">Drop or choose a <b>.zip</b> target</div>
        <div className="text-xs text-muted-foreground">go · java · python · js · ts · php · c# · ruby · kotlin · swift · rust · c++ — auto-detect</div>
        <input ref={fileRef} type="file" accept=".zip" hidden onChange={(e) => onFile(e.target.files?.[0])} />
        <Button onClick={() => fileRef.current?.click()} disabled={busy}>
          {busy ? "Scanning…" : "Choose .zip"}
        </Button>
        {err && <div className="text-sm text-red-500">{err}</div>}
      </Card>

      {sources.length > 0 && (
        <div>
          <div className="font-medium mb-3">Uploaded sources ({sources.length})</div>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {sources.map((s) => {
              const ts = s.result.targets ?? [s.result as Target];
              const nf = ts.reduce((a, t) => a + ((t.findings || []).length), 0);
              const funcs = ts.reduce((a, t) => a + ((t.summary?.functions) || 0), 0);
              const langs = [...new Set(ts.map((t) => t.summary?.language).filter(Boolean))].join(" · ") || "—";
              return (
                <Card key={s.id} className="p-3 text-sm">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold">{s.name}</span>
                    <button className="text-red-500 text-xs" onClick={() => del(s.id)}>✕</button>
                  </div>
                  <div className="text-muted-foreground text-xs mt-1">{ts.length} target · {funcs} funcs · {nf} findings · {langs}</div>
                  <div className="mt-2">
                    <Button size="sm" variant="outline" onClick={() => router.push(`/sast/graph?src=${s.id}`)}>◈ View graph</Button>
                  </div>
                </Card>
              );
            })}
          </div>
        </div>
      )}

      {registry.filter((e) => e.origin === "task").length > 0 && (
        <div>
          <div className="font-medium mb-1">Sources from New Task</div>
          <p className="text-sm text-muted-foreground mb-3">Uploaded while creating a review task — scan one here to view its call graph (the two upload paths are synced).</p>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {registry.filter((e) => e.origin === "task").map((e) => (
              <Card key={e.id} className="p-3 text-sm">
                <div className="font-semibold truncate" title={e.path}>{e.name}</div>
                <div className="text-muted-foreground text-xs mt-1">task upload · {e.files} files</div>
                <div className="mt-2">
                  <Button size="sm" variant="outline" disabled={busy} onClick={() => void scanById(e.id, e.name)}>
                    {busy ? "Scanning…" : "▶ Scan & view graph"}
                  </Button>
                </div>
              </Card>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
