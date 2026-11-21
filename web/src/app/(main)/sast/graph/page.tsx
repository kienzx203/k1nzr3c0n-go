"use client";

import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  ReactFlow, Background, Controls, MiniMap, MarkerType, Position, useNodesState,
  type Node, type Edge, type NodeMouseHandler,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import dagre from "dagre";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

type GNode = { id: string; label?: string; finding?: boolean; root?: boolean; entry?: boolean; source?: boolean; deep?: boolean; pos?: string; code?: string; file?: string; line?: number; end?: number; sinks?: number[] };
type GEdge = { source: string; target: string; label?: string };
type Graph = { nodes?: GNode[]; edges?: GEdge[]; files?: Record<string, string> };
type FlowStep = { func?: string; line?: number; role?: string; var?: string; desc?: string };
type Finding = {
  category?: string; func?: string; pos?: string; line?: number; sink?: string; sink_note?: string;
  source?: string; severity?: string; confidence?: number; interproc?: boolean; weak_sanitizer?: boolean;
  verdict?: string; verify_reason?: string; flow?: FlowStep[]; search?: boolean; rule_id?: string; also?: string[];
};
type Target = { name?: string; target?: string; summary?: { functions?: number; language?: string }; findings?: Finding[]; graph?: Graph };
type Result = { targets?: Target[]; graph?: Graph };
type Source = { id: string; name: string; result: Result; regId?: string };
// AgentFinding is a source→sink the review agent added during a task run (sast_add_flow).
type AgentFinding = { vulnclass?: string; severity?: string; source?: string; sink?: string; flow?: string; message?: string; worker?: string; task_id?: number; ts?: number };

function loadSources(): Source[] {
  try { return JSON.parse(localStorage.getItem("sastk1nz.sources") || "[]"); } catch { return []; }
}
function authToken(): string {
  try { return localStorage.getItem("artex_token") || ""; } catch { return ""; }
}
function cleanPos(p?: string): string {
  if (!p) return "";
  const m = p.match(/(?:^|\/)(?:src\/)?(.*)$/);
  return (m ? m[1] : p).replace(/^.*?\/src\//, "");
}

// A `<module>` node is a file's TOP-LEVEL code (statements outside any function) —
// where most PHP/script vulnerabilities live. Label it with its filename so the
// many module nodes are distinguishable, instead of an identical "<module>".
function dispLabel(n: GNode): string {
  const name = String(n.label || n.id);
  if (name === "<module>" || name.endsWith(".<module>") || name.endsWith("<module>")) {
    const file = (n.file || "").split("/").pop() || "file";
    return `▦ ${file} «top-level»`;
  }
  return name;
}

function build(g: Graph, focus: string | null) {
  const gn = g.nodes || [];
  const ge = (g.edges || []).filter((e) => e.source && e.target);
  const out = new Map<string, string[]>(), inc = new Map<string, string[]>();
  gn.forEach((n) => { out.set(String(n.id), []); inc.set(String(n.id), []); });
  ge.forEach((e) => {
    const s = String(e.source), t = String(e.target);
    if (out.has(s) && inc.has(t)) { out.get(s)!.push(t); inc.get(t)!.push(s); }
  });
  let keep: Set<string>;
  if (focus) {
    // VERTICAL source→sink chain. The focused function is where the sink lives
    // (bottom). Follow a SINGLE caller path UPWARD toward the entry (top) — one
    // caller per hop — so the result is a narrow column, NOT a wide fan-out. This
    // is what makes the picture tall/vertical instead of a wide band.
    keep = new Set([focus]);
    let cur = focus, guard = 0;
    while (guard++ < 60) {
      const callers = inc.get(cur) || [];
      // prefer an entry/root caller when present, else the first unused caller
      const next = callers.find((c) => !keep.has(c) && (inc.get(c) || []).length === 0)
        || callers.find((c) => !keep.has(c));
      if (!next) break;
      keep.add(next);
      cur = next;
    }
    // include the focus's own direct callees only if they are themselves sinks
    // (the actual dangerous call) — keeps the column meaningful without fanning out.
    for (const d of out.get(focus) || []) {
      const dn = gn.find((x) => String(x.id) === d);
      if (dn?.finding) keep.add(d);
    }
  } else {
    // Full-graph view renders up to a cap for responsiveness, prioritising
    // finding/entry nodes; EVERY function is still in the data and reachable via
    // search or by clicking a node (focus). No function is dropped from the graph.
    const CAP = 1200;
    if (gn.length <= CAP) {
      keep = new Set(gn.map((n) => String(n.id)));
    } else {
      const prio = [...gn].sort((a, b) => (Number(b.finding || b.root || b.entry) - Number(a.finding || a.root || a.entry)));
      keep = new Set(prio.slice(0, CAP).map((n) => String(n.id)));
    }
  }
  // dagre hierarchical TOP-DOWN (vertical) layout, IDA-style, monochrome.
  const W = 230, H = 58;
  const dg = new dagre.graphlib.Graph();
  // TB = top→bottom vertical flow (callers above, callees below). Generous nodesep
  // (horizontal gap between siblings) + edgesep spread parallel edges apart so the
  // connector lines don't overlap; network-simplex ranking minimises edge crossings.
  dg.setGraph({
    rankdir: "TB", nodesep: 55, ranksep: 95, edgesep: 28,
    marginx: 30, marginy: 30, ranker: "network-simplex", align: "UL",
  });
  dg.setDefaultEdgeLabel(() => ({}));
  [...keep].forEach((id) => dg.setNode(id, { width: W, height: H }));
  ge.forEach((e) => { const s = String(e.source), t = String(e.target); if (keep.has(s) && keep.has(t)) dg.setEdge(s, t); });
  dagre.layout(dg);

  const lbl = new Map(gn.map((n) => [String(n.id), n]));
  const nodes: Node[] = [...keep].map((id) => {
    const n = lbl.get(id)!;
    const d = dg.node(id);
    const isFocus = id === focus;
    // standard taint reading: source → … → sink. sink(finding)=red, source=green,
    // entry/root=blue, else neutral. deep/recall-discovered get a dashed border.
    const border = isFocus ? "#e6e6e6" : n?.finding ? "#8a4149" : n?.source ? "#3c7a4a" : (n?.root || n?.entry) ? "#3c5c66" : "#33424a";
    const tag = n?.finding ? "⊗ " : n?.source ? "▸ " : "";
    const loc = n?.file ? `${n.file}:${n.line ?? "?"}` : (n?.line ? `:${n.line}` : "");
    return {
      id, position: { x: (d?.x ?? 0) - W / 2, y: (d?.y ?? 0) - H / 2 },
      sourcePosition: Position.Bottom, targetPosition: Position.Top,  // vertical TB flow
      data: {
        label: (
          <div style={{ textAlign: "left", width: "100%" }}>
            <div style={{ whiteSpace: "normal", wordBreak: "break-word" }}>{tag + dispLabel(n).slice(0, 60)}</div>
            {loc && (
              <div title={loc} style={{ fontSize: 9, color: "#64757c", marginTop: 3, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", direction: "rtl" }}>
                {loc}
              </div>
            )}
          </div>
        ),
      },
      style: {
        fontFamily: "var(--font-mono, monospace)", fontSize: 11, borderRadius: 2,
        width: W, padding: "6px 9px", color: isFocus ? "#f2f2f2" : "#c2ccc7",
        background: isFocus ? "#1a1d1a" : "#0c1013",
        border: `${isFocus ? 2 : 1}px ${n?.deep ? "dashed" : "solid"} ${border}`, textAlign: "left", lineHeight: 1.15,
      },
    };
  });
  const edges: Edge[] = ge
    .filter((e) => keep.has(String(e.source)) && keep.has(String(e.target)))
    .slice(0, 2500)
    .map((e, i) => ({
      id: `e${i}`, source: String(e.source), target: String(e.target), type: "smoothstep",
      markerEnd: { type: MarkerType.ArrowClosed, color: "#5a6b72", width: 14, height: 14 },
      style: { stroke: "#4a5a61", strokeWidth: 1 },
    }));
  return { nodes, edges, out, inc, lbl };
}

// Real source view: renders the actual file, defaulting to the focused
// function's extent (decl line → line before next function), line-numbered,
// with sink lines highlighted. Toggle to expand to the whole file.
function sevColor(s?: string): string {
  return s === "high" ? "#ff3b5c" : s === "medium" ? "#ffb020"
    : s === "needs-review" ? "#16e0ff" : s === "low" ? "#8ff0c8" : "#9fb4bd";
}

// One file in a cross-file taint path: shows the code window around the taint
// steps in THIS file, with a per-file toggle to expand to the FULL file. Sink
// lines are red, other taint steps green; the first step scrolls into view.
function FileSnippet({ file, text, steps }: { file: string; text: string; steps: FlowStep[] }) {
  const [full, setFull] = useState(false);
  const hitRef = useRef<HTMLDivElement>(null);
  const flines = text.split("\n");
  const nums = steps.map((s) => s.line as number).filter(Boolean);
  const marks = new Set(nums);
  const sinkLines = new Set(steps.filter((s) => (s.role || "") === "sink").map((s) => s.line as number));
  const firstMark = Math.min(...nums);
  const lo = full ? 1 : Math.max(1, firstMark - 2);
  const hi = full ? flines.length : Math.min(flines.length, Math.max(...nums) + 2);
  useEffect(() => { hitRef.current?.scrollIntoView({ block: "center" }); }, [full]);
  const rows = [];
  for (let ln = lo; ln <= hi; ln++) {
    const hit = marks.has(ln), isSink = sinkLines.has(ln);
    rows.push(
      <div key={ln} ref={ln === firstMark ? hitRef : undefined} className="flex" style={{ background: isSink ? "#2a0a12" : hit ? "#13241c" : undefined }}>
        <span className="select-none pr-2 text-right text-[#4b5a60]" style={{ minWidth: 38 }}>{ln}</span>
        <span className="flex-1 whitespace-pre" style={{ color: isSink ? "#ff8a9c" : hit ? "#c8f7d8" : "#8a9aa0", borderLeft: isSink ? "2px solid #ff3b5c" : hit ? "2px solid #3c9c6c" : "2px solid transparent", paddingLeft: 6 }}>{(flines[ln - 1] || "").slice(0, 400)}</span>
      </div>,
    );
  }
  return (
    <div className="mt-1 overflow-hidden rounded border" style={{ borderColor: "#23323a" }}>
      <div className="flex items-center gap-1 bg-[#0b1317] px-2 py-1 text-[10px] text-[#7aa0ad]">
        <span>▦</span><span className="font-medium">{file}</span>
        <span className="text-[#4b5a60]">· {full ? `full file (${flines.length} lines)` : `lines ${lo}–${hi}`}</span>
        <button className="ml-auto text-[#16e0ff] hover:underline" onClick={() => setFull((v) => !v)}>{full ? "focus" : "full file"}</button>
      </div>
      <div className="overflow-auto bg-[#05090b] p-1.5 font-mono text-[10px] leading-relaxed" style={{ maxHeight: full ? 420 : 180 }}>{rows}</div>
    </div>
  );
}

// One vulnerability with its full source→sink taint path, each step showing the
// line, what happened, and the actual code — the "world-class" source→sink view.
function FindingCard({ f, files, lbl }: { f: Finding; files: Record<string, string>; lbl?: Map<string, GNode> }) {
  const [open, setOpen] = useState(true);
  const col = sevColor(f.severity);
  const p = String(f.pos || "").replace(/:\d+(:\d+)?$/, "");
  const fileKey = (want: string) =>
    Object.keys(files).find((k) => want === k || want.endsWith("/" + k) || want.endsWith(k) || k.endsWith(want)) || "";
  const key = fileKey(p);
  const lines = key ? (files[key] || "").split("\n") : [];
  // resolve the FILE a flow step lives in (steps can cross files on an interproc
  // path) via the node map: step.func is the call-graph key == a graph node id.
  const stepFileOf = (s: FlowStep): string => {
    const nf = s.func && lbl ? lbl.get(String(s.func))?.file : "";
    return (nf && fileKey(nf)) || key;
  };
  // does this finding's taint path span more than one file?
  const flowFiles = Array.from(new Set((f.flow || []).map(stepFileOf).filter(Boolean)));
  const multiFile = flowFiles.length > 1;
  return (
    <div className="rounded-md border p-2" style={{ borderColor: col + "66", background: col + "0d" }}>
      <button className="flex w-full items-center gap-2 flex-wrap text-left" onClick={() => setOpen(!open)}>
        <span className="rounded px-1.5 py-0.5 text-[10px] font-semibold" style={{ background: col + "22", color: col }}>{f.severity || "?"}</span>
        <span className="font-semibold">{f.category}</span>
        {(f.also || []).map((c) => <span key={c} className="rounded bg-muted px-1 text-[9px] text-muted-foreground">{c}</span>)}
        {typeof f.confidence === "number" && <span className="text-[10px] text-muted-foreground">conf {Math.round((f.confidence || 0) * 100)}%</span>}
        {f.interproc && <span className="rounded bg-sky-500/15 px-1 text-[10px] text-sky-400">interproc</span>}
        {f.weak_sanitizer && <span className="rounded bg-amber-500/15 px-1 text-[10px] text-amber-400">weak-sanitizer</span>}
        {f.verdict && <span className="text-[10px] text-muted-foreground">· {f.verdict}</span>}
        <span className="ml-auto text-[10px] text-muted-foreground">{open ? "▾" : "▸"}</span>
      </button>
      {open && (
        <>
          {f.sink_note && <div className="mt-1 text-[11px] text-muted-foreground">{f.sink_note}</div>}
          <div className="mt-1 text-[11px]">
            <span className="text-[#5fd08a]">source:</span> {String(f.source || "?")}
            <span className="mx-1 text-muted-foreground">→</span>
            <span className="text-[#ff8a9c]">sink:</span> {f.sink} <span className="text-muted-foreground">(L{f.line})</span>
          </div>
          {f.flow && f.flow.length > 0 && (
            <div className="mt-2 rounded border-l-2 bg-[#05090b] py-1 pl-2 pr-1" style={{ borderColor: "#3c5c66" }}>
              <div className="mb-1 flex items-center gap-2">
                <span className="text-[10px] uppercase tracking-wide text-muted-foreground">taint flow · source → sink</span>
                {multiFile && <span className="rounded bg-sky-500/15 px-1 text-[9px] text-sky-400">crosses {flowFiles.length} files</span>}
              </div>
              {(() => { let prevFile = ""; return f.flow.map((s, i) => {
                const role = s.role || "step";
                const icon = role === "source" ? "▸" : role === "sink" ? "⊗" : role === "call" ? "→" : "↓";
                const c = role === "source" ? "#5fd08a" : role === "sink" ? "#ff3b5c" : "#9fb4bd";
                const sfile = stepFileOf(s);
                const slines = sfile === key ? lines : (files[sfile] || "").split("\n");
                const code = (s.line && slines.length) ? (slines[(s.line || 1) - 1] || "").trim() : "";
                const badge = role === "source" ? "SOURCE" : role === "sink" ? "SINK" : role === "call" ? "CALL" : "STEP";
                // show a file header whenever the taint path crosses into another file
                const fileChanged = sfile && sfile !== prevFile;
                prevFile = sfile;
                return (
                  <div key={i} className="py-0.5">
                    {fileChanged && (
                      <div className="mb-0.5 mt-1 flex items-center gap-1 text-[10px] text-[#7aa0ad]">
                        <span>▦</span><span className="font-medium">{sfile}</span>
                      </div>
                    )}
                    <div className="flex items-baseline gap-2">
                      <span style={{ color: c }}>{icon}</span>
                      <span className="rounded px-1 text-[9px] font-semibold" style={{ background: c + "22", color: c, minWidth: 48, textAlign: "center" }}>{badge}</span>
                      <span className="text-[10px] text-[#4b5a60]" style={{ minWidth: 34 }}>L{s.line}</span>
                      <span className="flex-1" style={{ color: c }}>{s.desc || s.var || role}</span>
                    </div>
                    {code && <div className="ml-[4.6rem] mt-0.5 whitespace-pre-wrap break-all rounded bg-black/30 px-1.5 py-0.5 font-mono text-[10px] text-[#c8d6cf]">{code.slice(0, 160)}</div>}
                  </div>
                );
              }); })()}
            </div>
          )}
          {multiFile && (
            <div className="mt-2">
              <div className="mb-1 text-[10px] uppercase tracking-wide text-muted-foreground">source across files · {flowFiles.length}</div>
              {flowFiles.map((file) => {
                const steps = (f.flow || []).filter((s) => stepFileOf(s) === file && s.line);
                if (!steps.length || !(files[file] || "")) return null;
                return <FileSnippet key={file} file={file} text={files[file] || ""} steps={steps} />;
              })}
            </div>
          )}
        </>
      )}
    </div>
  );
}

function SourceBlock({ files, node }: { files: Record<string, string>; node: GNode }) {
  const [full, setFull] = useState(false);
  const declRef = useRef<HTMLDivElement>(null);
  const text = node.file ? files[node.file] : "";
  useEffect(() => { setFull(false); }, [node.id]);
  useEffect(() => { declRef.current?.scrollIntoView({ block: "center" }); }, [node.id, full]);

  if (!text) {
    return node.code
      ? <pre className="rounded-md border bg-[#05090b] p-2 overflow-auto text-[11px] leading-relaxed text-[#c8f7d8] whitespace-pre">{node.code}</pre>
      : <div className="text-muted-foreground">(no source captured — re-scan to include code)</div>;
  }
  const lines = text.split("\n");
  const start = node.line || 1;
  const end = node.end || Math.min(lines.length, start + 80);
  const lo = full ? 1 : Math.max(1, start - 1);
  const hi = full ? lines.length : Math.min(lines.length, end);
  const sinks = new Set(node.sinks || []);
  const rows = [];
  for (let ln = lo; ln <= hi; ln++) {
    const isSink = sinks.has(ln), isDecl = ln === start;
    rows.push(
      <div key={ln} ref={isDecl ? declRef : undefined}
        className="flex" style={{ background: isSink ? "#2a0a12" : isDecl ? "#13241c" : undefined }}>
        <span className="select-none pr-3 text-right text-[#4b5a60]" style={{ minWidth: 44 }}>{ln}</span>
        <span className="flex-1 whitespace-pre" style={{ color: isSink ? "#ff8a9c" : "#c8d6cf", borderLeft: isSink ? "2px solid #ff3b5c" : isDecl ? "2px solid #3c9c6c" : "2px solid transparent", paddingLeft: 6 }}>{lines[ln - 1] || ""}</span>
      </div>,
    );
  }
  return (
    <div>
      <div className="mb-1 flex items-center justify-between">
        <span className="font-medium">◂ Source {full ? "(full file)" : `(lines ${lo}–${hi})`}</span>
        <button className="text-[11px] text-[#16e0ff] hover:underline" onClick={() => setFull((v) => !v)}>
          {full ? "show function" : "show full file"}
        </button>
      </div>
      <div className="rounded-md border bg-[#05090b] p-2 overflow-auto text-[11px] leading-relaxed font-mono" style={{ maxHeight: full ? 460 : 300 }}>
        {rows}
      </div>
    </div>
  );
}

function GraphView({ source, onBack }: { source: Source; onBack: () => void }) {
  const targets: Target[] = source.result.targets ?? [source.result as Target];
  const [ti, setTi] = useState(0);
  const [focus, setFocus] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [showList, setShowList] = useState(true);
  const [sevFilter, setSevFilter] = useState<string | null>(null);
  // Agent-added source→sink findings (sast_add_flow during a review task), overlaid on this SAST graph.
  const [agentF, setAgentF] = useState<AgentFinding[]>([]);
  const [showAgent, setShowAgent] = useState(true);
  useEffect(() => {
    if (!source.regId) { setAgentF([]); return; }
    fetch(`/api/sast/agent-findings?id=${encodeURIComponent(source.regId)}`, { headers: { Authorization: `Bearer ${authToken()}` } })
      .then((r) => (r.ok ? r.json() : { findings: [] }))
      .then((d) => setAgentF((d.findings as AgentFinding[]) || []))
      .catch(() => setAgentF([]));
  }, [source.regId]);
  const g = targets[ti]?.graph ?? { nodes: [], edges: [] };
  const files = g.files || {};
  // all taint vulnerabilities in this target, severity-ranked (for the list panel).
  const SEV_RANK: Record<string, number> = { high: 0, medium: 1, "needs-review": 2, low: 3 };
  const vulns = useMemo(() => {
    const v = (targets[ti]?.findings || []).filter((f) => !f.search);
    return v.slice().sort((a, b) =>
      (SEV_RANK[a.severity || ""] ?? 9) - (SEV_RANK[b.severity || ""] ?? 9) ||
      (b.confidence || 0) - (a.confidence || 0));
  }, [targets, ti]);
  const sevCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const f of vulns) c[f.severity || "?"] = (c[f.severity || "?"] || 0) + 1;
    return c;
  }, [vulns]);
  // index taint findings by the function they live in, so clicking a node shows its
  // findings + the full source→sink taint path.
  const findingsByFunc = useMemo(() => {
    const m = new Map<string, Finding[]>();
    for (const f of (targets[ti]?.findings || [])) {
      if (f.search) continue;
      const k = String(f.func || "");
      if (!m.has(k)) m.set(k, []);
      m.get(k)!.push(f);
    }
    return m;
  }, [targets, ti]);
  // Default to a CLEAN VERTICAL view: focus a real SINK node in the graph (one with
  // finding=true, whose id always matches a node) so the opening view is a narrow
  // source→sink column, not a wide band. Full overview is one click away ("✕ Full graph").
  useEffect(() => {
    setQ("");
    const nodes = targets[ti]?.graph?.nodes || [];
    const topFunc = vulns.find((f) => f.func && nodes.some((n) => String(n.id) === String(f.func)))?.func;
    const sinkNode = nodes.find((n) => n.finding);
    setFocus(topFunc ? String(topFunc) : sinkNode ? String(sinkNode.id) : null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ti]);

  const { nodes, edges, out, inc, lbl } = useMemo(() => build(g, focus), [g, focus]);
  // controlled node state so DRAGGING actually sticks (a bare `nodes={...}` prop is
  // controlled and ignores drags without onNodesChange). Re-sync when the layout
  // recomputes (target/focus change).
  const [rfNodes, setRfNodes, onNodesChange] = useNodesState<Node>([]);
  useEffect(() => { setRfNodes(nodes); }, [nodes, setRfNodes]);
  const onNodeClick: NodeMouseHandler = useCallback((_e, n) => { setFocus(n.id); setQ(""); }, []);

  const matches = useMemo(() => {
    const s = q.trim().toLowerCase();
    if (!s) return [];
    return (g.nodes || []).filter((n) => (dispLabel(n) + " " + (n.label || n.id)).toLowerCase().includes(s)).slice(0, 14);
  }, [q, g]);

  const fn = focus ? lbl.get(focus) : null;
  const detail = fn ? {
    label: dispLabel(fn), pos: cleanPos(fn.pos), code: fn.code || "",
    isModule: String(fn.label || "").endsWith("<module>"),
    callers: (inc.get(focus!) || []).map((id) => ({ id, label: lbl.get(id) ? dispLabel(lbl.get(id)!) : id })),
    calls: (out.get(focus!) || []).map((id) => ({ id, label: lbl.get(id) ? dispLabel(lbl.get(id)!) : id })),
  } : null;

  return (
    <div className="flex h-[calc(100vh-56px)] flex-col">
      <div className="flex items-center gap-3 border-b px-4 py-2">
        <Button size="sm" variant="ghost" onClick={onBack}>← Sources</Button>
        <span className="text-sm font-medium">{source.name}</span>
        {targets.length > 1 && (
          <select className="rounded-md border bg-background px-2 py-1 text-xs" value={ti} onChange={(e) => setTi(Number(e.target.value))}>
            {targets.map((t, i) => (<option key={i} value={i}>{t.name || t.target || "/"} ({t.graph?.nodes?.length ?? 0})</option>))}
          </select>
        )}
        <div className="relative">
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="🔎 search function…" className="h-8 w-56 text-xs" />
          {matches.length > 0 && (
            <div className="absolute z-20 mt-1 max-h-72 w-72 overflow-auto rounded-md border bg-popover p-1 shadow-xl">
              {matches.map((m) => (
                <button key={m.id} className="block w-full truncate rounded px-2 py-1 text-left text-xs hover:bg-accent"
                  onClick={() => { setFocus(String(m.id)); setQ(""); }}>
                  <span className={m.finding ? "text-[#ff3b5c]" : ""}>{dispLabel(m)}</span>
                </button>
              ))}
            </div>
          )}
        </div>
        {focus && <Button size="sm" variant="outline" onClick={() => setFocus(null)}>✕ Full graph</Button>}
        <Button size="sm" variant={showList ? "default" : "outline"} onClick={() => setShowList(!showList)}>
          ⊗ Vulnerabilities ({vulns.length})
        </Button>
        {agentF.length > 0 && (
          <Button size="sm" variant={showAgent ? "default" : "outline"} onClick={() => setShowAgent(!showAgent)}>
            🤖 Agent findings ({agentF.length})
          </Button>
        )}
        <span className="flex items-center gap-1 text-[11px]">
          {Object.entries(sevCounts).map(([s, c]) => (
            <span key={s} className="rounded px-1.5 py-0.5 font-medium" style={{ background: sevColor(s) + "22", color: sevColor(s) }}>{c} {s}</span>
          ))}
        </span>
        <span className="ml-auto text-xs text-muted-foreground">
          {focus ? `${nodes.length} nodes` : `${nodes.length}/${(g.nodes || []).length} funcs`} · {edges.length} edges
          {!focus && (g.nodes || []).length > nodes.length && <span className="ml-1 text-amber-500/70">(all searchable)</span>}
          <span className="ml-3"><i className="inline-block h-2 w-3 align-middle" style={{ border: "1px solid #8a4149" }} /> ⊗ sink</span>
          <span className="ml-2"><i className="inline-block h-2 w-3 align-middle" style={{ border: "1px solid #3c5c66" }} /> entry</span>
          <span className="ml-2"><i className="inline-block h-2 w-3 align-middle" style={{ border: "2px solid #e6e6e6" }} /> selected</span>
        </span>
      </div>
      <div className="relative flex-1">
        {showAgent && agentF.length > 0 && (
          <Card className="absolute right-3 top-3 z-10 flex w-[28rem] max-h-[92%] flex-col overflow-hidden p-0 shadow-xl border-sky-500/40">
            <div className="flex items-center gap-2 border-b px-3 py-2">
              <span className="text-sm font-semibold text-sky-400">🤖 Agent-added findings ({agentF.length})</span>
              <button className="ml-auto text-xs text-muted-foreground hover:text-foreground" onClick={() => setShowAgent(false)}>✕</button>
            </div>
            <div className="overflow-auto p-2 space-y-2 text-xs">
              <div className="text-[11px] text-muted-foreground px-1">Source→sink confirmed by the review agent during task runs (via sast_add_flow).</div>
              {agentF.map((f, i) => (
                <div key={i} className="rounded border p-2 space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="rounded px-1.5 py-0.5 text-[10px] font-medium" style={{ background: sevColor(f.severity || "") + "22", color: sevColor(f.severity || "") }}>{f.severity || "?"}</span>
                    <span className="font-semibold">{f.vulnclass || "finding"}</span>
                    {f.task_id ? <span className="ml-auto text-[10px] text-muted-foreground">task #{f.task_id}</span> : null}
                  </div>
                  {f.message && <div className="text-muted-foreground">{f.message}</div>}
                  {f.source && <div><span className="text-[#16e0ff]">SOURCE</span> {f.source}</div>}
                  {f.sink && <div><span className="text-[#ff8a9c]">SINK</span> {f.sink}</div>}
                  {f.flow && <div className="break-all text-muted-foreground"><span className="text-[#8ff0c8]">FLOW</span> {f.flow}</div>}
                </div>
              ))}
            </div>
          </Card>
        )}
        {showList && vulns.length > 0 && (
          <Card className="absolute left-3 top-3 z-10 flex w-[26rem] max-h-[92%] flex-col overflow-hidden p-0 shadow-xl">
            <div className="flex items-center gap-2 border-b px-3 py-2">
              <span className="text-sm font-semibold text-[#ff8a9c]">⊗ Vulnerabilities ({vulns.length})</span>
              <div className="ml-auto flex gap-1">
                {["high", "medium", "needs-review", "low"].filter((s) => sevCounts[s]).map((s) => (
                  <button key={s} onClick={() => setSevFilter(sevFilter === s ? null : s)}
                    className="rounded px-1.5 py-0.5 text-[10px] font-medium"
                    style={{ background: sevColor(s) + (sevFilter === s ? "44" : "18"), color: sevColor(s), outline: sevFilter === s ? "1px solid " + sevColor(s) : "none" }}>
                    {s}
                  </button>
                ))}
                {sevFilter && <button onClick={() => setSevFilter(null)} className="text-[10px] text-muted-foreground">✕</button>}
              </div>
            </div>
            <div className="overflow-auto">
              {vulns.filter((f) => !sevFilter || f.severity === sevFilter).map((f, i) => (
                <button key={i} onClick={() => { setFocus(String(f.func || "")); setQ(""); }}
                  className={`block w-full border-b px-3 py-2 text-left hover:bg-accent ${focus === f.func ? "bg-accent/60" : ""}`}>
                  <div className="flex items-center gap-2">
                    <span className="inline-block h-2 w-2 rounded-full" style={{ background: sevColor(f.severity) }} />
                    <span className="text-xs font-semibold">{f.category}</span>
                    {(f.also || []).map((c) => <span key={c} className="rounded bg-muted px-1 text-[9px] text-muted-foreground">{c}</span>)}
                    <span className="text-[10px] text-muted-foreground">{f.severity}</span>
                    {f.interproc && <span className="rounded bg-sky-500/15 px-1 text-[9px] text-sky-400">interproc</span>}
                    <span className="ml-auto text-[10px] text-muted-foreground">{typeof f.confidence === "number" ? Math.round(f.confidence * 100) + "%" : ""}</span>
                  </div>
                  <div className="mt-1 text-[11px] leading-snug">
                    <span className="text-[#5fd08a]">▸ {String(f.source || "?").slice(0, 40)}</span>
                    <span className="mx-1 text-muted-foreground">⟶</span>
                    <span className="text-[#ff8a9c]">⊗ {f.sink}</span>
                  </div>
                  <div className="truncate text-[10px] text-muted-foreground">
                    {cleanPos(f.pos).replace(/:\d+(:\d+)?$/, "")}<span className="text-[#ffb020]">:{f.line}</span>
                  </div>
                </button>
              ))}
            </div>
          </Card>
        )}
        {nodes.length === 0 ? (
          <div className="flex h-full items-center justify-center text-sm text-muted-foreground">No graph for this target.</div>
        ) : (
          <ReactFlow
            key={`${ti}-${focus || "full"}`}
            nodes={rfNodes} edges={edges} onNodeClick={onNodeClick} onNodesChange={onNodesChange}
            fitView minZoom={0.03} nodesDraggable nodesConnectable={false} elementsSelectable
            proOptions={{ hideAttribution: true }}
          >
            <Background color="#1c2a30" gap={26} />
            <MiniMap pannable zoomable />
            <Controls />
          </ReactFlow>
        )}
        {detail && (
          <Card className="absolute right-3 top-3 flex w-[34rem] max-h-[90%] flex-col overflow-hidden p-0 shadow-xl">
            <div className="border-b px-3 py-2">
              <div className="font-semibold text-sm text-amber-400 break-all">{detail.label}</div>
              {detail.pos && <div className="text-[11px] text-muted-foreground mt-0.5 break-all">{detail.pos}</div>}
              {detail.isModule && <div className="text-[11px] text-sky-400/80 mt-1">File-level code — statements outside any function (common place for script vulnerabilities).</div>}
            </div>
            <div className="overflow-auto p-3 text-xs space-y-3">
              {focus && (findingsByFunc.get(focus) || []).length > 0 && (
                <div className="space-y-2">
                  <div className="font-medium text-[#ff8a9c]">⊗ Vulnerabilities in this function ({(findingsByFunc.get(focus) || []).length})</div>
                  {(findingsByFunc.get(focus) || []).map((f, i) => <FindingCard key={i} f={f} files={files} lbl={lbl} />)}
                </div>
              )}
              {fn && <SourceBlock files={files} node={fn} />}
              <div>
                <div className="font-medium">↑ Called by ({detail.callers.length}) <span className="text-muted-foreground font-normal">— toward source</span></div>
                {detail.callers.length ? detail.callers.map((c) => (
                  <button key={c.id} className="block w-full truncate text-left text-[#16e0ff] hover:underline" onClick={() => setFocus(c.id)}>{c.label}</button>
                )) : <div className="text-muted-foreground">— entry / no caller</div>}
              </div>
              <div>
                <div className="font-medium">↓ Calls ({detail.calls.length}) <span className="text-muted-foreground font-normal">— toward sink</span></div>
                {detail.calls.length ? detail.calls.map((c) => (
                  <button key={c.id} className="block w-full truncate text-left text-[#8ff0c8] hover:underline" onClick={() => setFocus(c.id)}>{c.label}</button>
                )) : <div className="text-muted-foreground">— leaf (sink)</div>}
              </div>
            </div>
            <div className="border-t p-2"><Button size="sm" variant="outline" className="w-full" onClick={() => setFocus(null)}>Back to full graph</Button></div>
          </Card>
        )}
      </div>
    </div>
  );
}

function SourceList({ sources, onPick }: { sources: Source[]; onPick: (id: string) => void }) {
  return (
    <div className="p-6 space-y-4">
      <h1 className="text-2xl font-semibold">Call Graph</h1>
      <p className="text-sm text-muted-foreground">Pick an uploaded source. Click a node (or search) to focus its source→sink call chain and view the function source.</p>
      {sources.length === 0 ? (
        <Card className="p-6 text-sm text-muted-foreground">No source uploaded yet — go to <a className="underline" href="/sast/upload">Upload</a>.</Card>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {sources.map((s) => {
            const ts = s.result.targets ?? [s.result as Target];
            const funcs = ts.reduce((a, t) => a + ((t.summary?.functions) || 0), 0);
            return (
              <Card key={s.id} className="p-3 text-sm cursor-pointer hover:border-primary" onClick={() => onPick(s.id)}>
                <div className="font-semibold">{s.name}</div>
                <div className="text-muted-foreground text-xs mt-1">{ts.length} target · {funcs} funcs</div>
                <div className="mt-2"><Button size="sm" variant="outline">◈ View graph</Button></div>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

function GraphInner() {
  const sp = useSearchParams();
  const router = useRouter();
  const [sources, setSources] = useState<Source[]>([]);
  useEffect(() => { setSources(loadSources()); }, []);
  const srcId = sp.get("src");
  const source = srcId ? sources.find((s) => s.id === srcId) : null;
  if (source) return <GraphView source={source} onBack={() => router.push("/sast/graph")} />;
  return <SourceList sources={sources} onPick={(id) => router.push(`/sast/graph?src=${id}`)} />;
}

export default function SastGraphPage() {
  return (<Suspense fallback={null}><GraphInner /></Suspense>);
}
