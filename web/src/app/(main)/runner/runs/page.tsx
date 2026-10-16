"use client";

import * as React from "react";
import { PlayCircleIcon, RefreshCwIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { k1z } from "@/lib/k1z";

interface Run {
  id: string;
  workflow: string;
  target: string;
  status: string;
  created_at?: string;
}

const STATUS_COLOR: Record<string, string> = {
  running: "text-blue-600",
  completed: "text-green-600",
  failed: "text-red-600",
  queued: "text-neutral-500",
  paused: "text-amber-600",
};

export default function RunsPage() {
  const [runs, setRuns] = React.useState<Run[]>([]);
  const [workflows, setWorkflows] = React.useState<string[]>([]);
  const [wf, setWf] = React.useState("");
  const [target, setTarget] = React.useState("");
  const [err, setErr] = React.useState("");
  const [logRun, setLogRun] = React.useState<string | null>(null);
  const [logs, setLogs] = React.useState<string[]>([]);
  const wsRef = React.useRef<WebSocket | null>(null);

  function openLogs(id: string) {
    setLogRun(id);
    setLogs([]);
    try {
      wsRef.current?.close();
    } catch {
      /* ignore */
    }
    let token = "";
    try {
      token = localStorage.getItem("artex_token") ?? "";
    } catch {
      /* ignore */
    }
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/ws/runs/${id}${token ? `?token=${encodeURIComponent(token)}` : ""}`);
    wsRef.current = ws;
    ws.onmessage = (ev) => {
      try {
        const m = JSON.parse(ev.data) as { type?: string; message?: string; status?: string };
        if (m.message) setLogs((l) => [...l.slice(-800), m.message!]);
        else if (m.type === "done") setLogs((l) => [...l, `— run ${m.status ?? "finished"} —`]);
      } catch {
        /* ignore */
      }
    };
  }
  React.useEffect(() => () => {
    try {
      wsRef.current?.close();
    } catch {
      /* ignore */
    }
  }, []);

  const load = React.useCallback(async () => {
    try {
      const r = (await k1z.get("/runs")) as { items?: Run[] };
      setRuns(r.items ?? []);
    } catch (e) {
      setErr((e as Error).message);
    }
  }, []);

  React.useEffect(() => {
    load();
    k1z
      .get("/workflows")
      .then((r) => {
        const list = (r as { workflows?: { name: string }[] }).workflows ?? [];
        const names = list.map((x) => x.name).filter(Boolean);
        setWorkflows(names);
        if (names[0]) setWf(names[0]);
      })
      .catch(() => {});
    const t = setInterval(load, 4000);
    return () => clearInterval(t);
  }, [load]);

  async function launch() {
    setErr("");
    if (!wf || !target.trim()) {
      setErr("Pick a workflow and enter a target");
      return;
    }
    try {
      await k1z.post("/runs", { workflow: wf, target: target.trim() });
      setTarget("");
      load();
    } catch (e) {
      setErr((e as Error).message);
    }
  }

  return (
    <div className="flex flex-col gap-4 p-4 md:p-6">
      <div>
        <h1 className="text-xl font-semibold">Runs</h1>
        <p className="text-muted-foreground text-sm">
          k1nzr3c0n workflow runner — launch a recon pipeline and watch its status.
        </p>
      </div>

      <Card>
        <CardContent className="flex flex-wrap items-end gap-2 p-4">
          <div className="flex flex-col gap-1">
            <label className="text-muted-foreground text-xs">Workflow</label>
            <select
              className="border-input bg-background h-9 rounded-md border px-2 text-sm"
              value={wf}
              onChange={(e) => setWf(e.target.value)}
            >
              {workflows.map((w) => (
                <option key={w} value={w}>
                  {w}
                </option>
              ))}
            </select>
          </div>
          <div className="flex min-w-[220px] flex-1 flex-col gap-1">
            <label className="text-muted-foreground text-xs">Target</label>
            <Input value={target} placeholder="example.com" onChange={(e) => setTarget(e.target.value)} />
          </div>
          <Button onClick={launch}>
            <PlayCircleIcon className="size-4" /> Launch run
          </Button>
          <Button variant="outline" onClick={load}>
            <RefreshCwIcon className="size-4" />
          </Button>
        </CardContent>
      </Card>

      {err && <p className="text-sm text-red-600">⚠ {err}</p>}

      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>Workflow</TableHead>
                <TableHead>Target</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Created</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {runs.map((r) => (
                <TableRow key={r.id} className="cursor-pointer" onClick={() => openLogs(r.id)}>
                  <TableCell className="font-mono text-xs text-blue-600">{r.id}</TableCell>
                  <TableCell>{r.workflow}</TableCell>
                  <TableCell className="font-mono">{r.target}</TableCell>
                  <TableCell className={STATUS_COLOR[r.status] ?? ""}>{r.status}</TableCell>
                  <TableCell className="text-muted-foreground text-xs">
                    {(r.created_at ?? "").replace("T", " ").slice(0, 19)}
                  </TableCell>
                </TableRow>
              ))}
              {runs.length === 0 && (
                <TableRow>
                  <TableCell colSpan={5} className="text-muted-foreground py-8 text-center">
                    No runs yet.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {logRun && (
        <Card>
          <CardContent className="p-0">
            <div className="flex items-center gap-2 border-b px-4 py-2">
              <span className="text-sm font-semibold">Live logs · run {logRun}</span>
              <Button
                className="ml-auto"
                variant="outline"
                size="sm"
                onClick={() => {
                  try {
                    wsRef.current?.close();
                  } catch {
                    /* ignore */
                  }
                  setLogRun(null);
                }}
              >
                Close
              </Button>
            </div>
            <pre className="bg-muted/30 max-h-[50vh] overflow-auto p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap">
              {logs.length ? logs.join("\n") : "Connecting…"}
            </pre>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
