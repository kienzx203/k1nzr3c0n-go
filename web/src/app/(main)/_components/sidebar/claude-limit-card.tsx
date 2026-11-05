"use client";

import * as React from "react";

import { api } from "@/lib/api";

type Snapshot = {
  host?: string;
  model?: string;
  sub?: boolean;
  status?: number;
  headers?: Record<string, string>;
  at?: string;
};

type Window = {
  token: string;
  util?: number; // 0..1 utilization (Anthropic unified windows)
  limit?: number;
  remaining?: number;
  reset?: string;
  status?: string;
};

// parseWindows groups captured rate-limit headers into usage windows by token (the
// part between "ratelimit-" and the field suffix). Handles Anthropic's unified
// utilization form (unified-5h-utilization=0.31 + -reset + -status) and the classic
// limit/remaining/reset form — name-agnostic across providers (Claude, opencode…).
function parseWindows(headers: Record<string, string>): Window[] {
  const wins: Record<string, Window> = {};
  for (const [k, v] of Object.entries(headers)) {
    let field: "util" | "limit" | "remaining" | "reset" | "status" | null = null;
    if (/-utilization$/.test(k)) field = "util";
    else if (/-limit$/.test(k)) field = "limit";
    else if (/-remaining$/.test(k)) field = "remaining";
    else if (/-reset$/.test(k)) field = "reset";
    else if (/-status$/.test(k)) field = "status";
    else continue;
    const token = k
      .replace(/^.*ratelimit-/, "")
      .replace(/^.*rate-limit-/, "")
      .replace(/^anthropic-/, "")
      .replace(/^unified-/, "")
      .replace(/-(utilization|limit|remaining|reset|status)$/, "");
    wins[token] = wins[token] ?? { token };
    if (field === "reset") wins[token].reset = v;
    else if (field === "status") wins[token].status = v;
    else if (field === "util") wins[token].util = Number(v);
    else wins[token][field] = Number(v);
  }
  return Object.values(wins);
}

// pctOf returns the used percentage for a window, or null if it has no usable metric.
function pctOf(w: Window): number | null {
  if (typeof w.util === "number" && !Number.isNaN(w.util)) {
    return Math.min(100, Math.max(0, Math.round(w.util * 100)));
  }
  if (typeof w.limit === "number" && w.limit > 0 && typeof w.remaining === "number") {
    return Math.min(100, Math.max(0, Math.round(((w.limit - w.remaining) / w.limit) * 100)));
  }
  return null;
}

function prettyToken(t: string): string {
  const m = t.toLowerCase();
  if (m.includes("5h") || m.includes("5-h") || m.includes("fiveh") || m.includes("hour")) return "5 giờ";
  if (m.includes("7d") || m.includes("week")) return "Tuần";
  if (m.includes("day") || m.includes("daily") || m.includes("24h")) return "Ngày";
  if (m.includes("request")) return "Requests";
  if (m.includes("input-token")) return "Input tokens";
  if (m.includes("output-token")) return "Output tokens";
  if (m.includes("token")) return "Tokens";
  return t;
}

function prettyHost(host?: string): string {
  if (!host) return "LLM";
  if (host.includes("anthropic")) return "Claude";
  if (host.includes("opencode")) return "opencode";
  return host.replace(/^www\./, "").split(".").slice(0, -1).join(".") || host;
}

function resetMs(reset?: string): number | null {
  if (!reset) return null;
  const n = Number(reset);
  if (!Number.isNaN(n)) {
    if (n > 1e12) return n;
    if (n > 1e9) return n * 1000;
    return Date.now() + n * 1000;
  }
  const t = Date.parse(reset);
  return Number.isNaN(t) ? null : t;
}

function countdown(ms: number | null): string {
  if (ms == null) return "";
  const d = Math.max(0, Math.floor((ms - Date.now()) / 1000));
  if (d >= 86400) return `${Math.floor(d / 86400)}d ${Math.floor((d % 86400) / 3600)}h`;
  if (d >= 3600) return `${Math.floor(d / 3600)}h ${Math.floor((d % 3600) / 60)}m`;
  if (d >= 60) return `${Math.floor(d / 60)}m`;
  return `${d}s`;
}

function ProviderBars({ snap }: { snap: Snapshot }) {
  const wins = parseWindows(snap.headers ?? {});
  const bars = wins
    .map((w) => ({ w, pct: pctOf(w) }))
    .filter((x): x is { w: Window; pct: number } => x.pct !== null)
    // 5h first, then weekly, then the rest
    .sort((a, b) => order(a.w.token) - order(b.w.token));
  if (bars.length === 0) return null;
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between text-[10px] text-muted-foreground">
        <span className="font-medium text-foreground/80">{prettyHost(snap.host)}</span>
        {snap.model && <span className="truncate">{snap.model}</span>}
      </div>
      {bars.map(({ w, pct }) => {
        const rem = countdown(resetMs(w.reset));
        const rejected = w.status && w.status !== "allowed";
        const danger = rejected || pct >= 90;
        const warn = pct >= 70;
        return (
          <div key={w.token} className="space-y-0.5">
            <div className="flex items-center justify-between text-[10px] text-muted-foreground">
              <span>{prettyToken(w.token)}</span>
              <span>
                {pct}%{rem ? ` · reset ${rem}` : ""}
              </span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
              <div
                className={`h-full rounded-full transition-[width] duration-500 ${
                  danger ? "bg-destructive" : warn ? "bg-amber-500" : "bg-primary"
                }`}
                style={{ width: `${pct}%` }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function order(token: string): number {
  const m = token.toLowerCase();
  if (m.includes("5h") || m.includes("hour")) return 0;
  if (m.includes("7d") || m.includes("week")) return 1;
  if (m.includes("day")) return 2;
  return 9;
}

/**
 * Compact LLM usage card in the sidebar footer. Polls the server's captured
 * rate-limit headers and renders a progress bar per usage window (5h / weekly / …)
 * per upstream provider (Claude, opencode). Silent until data exists.
 */
export function ClaudeLimitCard() {
  const [snaps, setSnaps] = React.useState<Snapshot[]>([]);
  const [, force] = React.useReducer((x: number) => x + 1, 0);

  React.useEffect(() => {
    let alive = true;
    const load = () =>
      api
        .llmRateLimits()
        .then((s) => alive && setSnaps(s ?? []))
        .catch(() => {});
    load();
    const poll = setInterval(load, 30000);
    const tick = setInterval(force, 30000); // refresh countdowns
    return () => {
      alive = false;
      clearInterval(poll);
      clearInterval(tick);
    };
  }, []);

  const providers = snaps.map((snap) => ({ snap, node: <ProviderBars key={snap.host ?? snap.model} snap={snap} /> }));
  const hasAny = providers.some((p) => p.node !== null && parseWindows(p.snap.headers ?? {}).some((w) => pctOf(w) !== null));

  if (!hasAny) {
    return (
      <div className="group-data-[collapsible=icon]:hidden px-2 py-1 text-[11px] text-muted-foreground/70">
        LLM limit: chưa có dữ liệu
      </div>
    );
  }

  return (
    <div className="group-data-[collapsible=icon]:hidden space-y-2 rounded-md border bg-muted/20 px-2 py-2">
      <div className="text-[11px] font-medium">LLM limit</div>
      {providers.map((p) => p.node)}
    </div>
  );
}
