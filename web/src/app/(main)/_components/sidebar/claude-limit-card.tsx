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

type Window = { token: string; limit?: number; remaining?: number; reset?: string };

// parseWindows groups captured rate-limit headers into windows by their token (the
// part between "ratelimit-" and the -limit/-remaining/-reset suffix). Name-agnostic
// so it works for unified-5h / 7d / requests / tokens, from Claude or opencode.
function parseWindows(headers: Record<string, string>): Window[] {
  const wins: Record<string, Window> = {};
  for (const [k, v] of Object.entries(headers)) {
    let field: "limit" | "remaining" | "reset" | null = null;
    if (/-limit$/.test(k)) field = "limit";
    else if (/-remaining$/.test(k)) field = "remaining";
    else if (/-reset$/.test(k)) field = "reset";
    if (!field) continue;
    const token = k
      .replace(/^.*ratelimit-/, "")
      .replace(/^.*rate-limit-/, "")
      .replace(/^anthropic-/, "")
      .replace(/-(limit|remaining|reset)$/, "");
    wins[token] = wins[token] ?? { token };
    if (field === "reset") wins[token].reset = v;
    else wins[token][field] = Number(v);
  }
  return Object.values(wins);
}

function prettyToken(t: string): string {
  const m = t.toLowerCase();
  if (m.includes("5h") || m.includes("5-h") || m.includes("fiveh")) return "5 giờ";
  if (m.includes("7d") || m.includes("week")) return "Tuần";
  if (m.includes("day") || m.includes("daily") || m.includes("24h")) return "Ngày";
  if (m.includes("hour")) return "Giờ";
  if (m.includes("request")) return "Requests";
  if (m.includes("input-token")) return "Input tokens";
  if (m.includes("output-token")) return "Output tokens";
  if (m.includes("token")) return "Tokens";
  if (m === "unified") return "Tổng";
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

function Bars({ snap }: { snap: Snapshot }) {
  const headers = snap.headers ?? {};
  const wins = parseWindows(headers);
  const bars = wins.filter((w) => typeof w.limit === "number" && w.limit > 0 && typeof w.remaining === "number");
  if (bars.length > 0) {
    return (
      <div className="space-y-1">
        {bars.map((w) => {
          const used = (w.limit as number) - (w.remaining as number);
          const pct = Math.min(100, Math.max(0, Math.round((used / (w.limit as number)) * 100)));
          const rem = countdown(resetMs(w.reset));
          const danger = pct >= 90;
          const warn = pct >= 70;
          return (
            <div key={w.token} className="space-y-0.5">
              <div className="flex items-center justify-between text-[10px] text-muted-foreground">
                <span>{prettyToken(w.token)}</span>
                <span>
                  {pct}%{rem ? ` · ${rem}` : ""}
                </span>
              </div>
              <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
                <div
                  className={`h-full rounded-full ${danger ? "bg-destructive" : warn ? "bg-amber-500" : "bg-primary"}`}
                  style={{ width: `${pct}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
    );
  }
  // No usable limit/remaining pair: show the raw captured headers so it's still useful.
  return (
    <div className="space-y-0.5">
      {Object.entries(headers).map(([k, v]) => (
        <div key={k} className="flex justify-between gap-2 text-[10px] text-muted-foreground">
          <span className="truncate">{k.replace(/^anthropic-ratelimit-/, "").replace(/^.*ratelimit-/, "")}</span>
          <span className="shrink-0 font-mono">{v}</span>
        </div>
      ))}
    </div>
  );
}

/**
 * Compact LLM usage card for the sidebar footer. Polls the server's latest captured
 * rate-limit headers and renders a bar per window, per upstream provider (Claude,
 * opencode, …). Silent-ish until a call has populated the data.
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
    const tick = setInterval(force, 30000);
    return () => {
      alive = false;
      clearInterval(poll);
      clearInterval(tick);
    };
  }, []);

  if (snaps.length === 0) {
    return (
      <div className="group-data-[collapsible=icon]:hidden px-2 py-1 text-[11px] text-muted-foreground/70">
        LLM limit: chưa có dữ liệu — chạy 1 lần
      </div>
    );
  }

  return (
    <div className="group-data-[collapsible=icon]:hidden space-y-2 rounded-md border bg-muted/20 px-2 py-2">
      <div className="text-[11px] font-medium">LLM limit</div>
      {snaps.map((snap) => (
        <div key={snap.host ?? snap.model} className="space-y-1">
          <div className="flex items-center justify-between text-[10px] text-muted-foreground">
            <span className="font-medium text-foreground/80">{prettyHost(snap.host)}</span>
            {snap.model && <span className="truncate">{snap.model}</span>}
          </div>
          <Bars snap={snap} />
        </div>
      ))}
    </div>
  );
}
