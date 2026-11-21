"use client";

import * as React from "react";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Card } from "@/components/ui/card";
import { toast } from "sonner";

const MISSIONS = [
  { key: "bugbounty", label: "Bug Bounty" },
  { key: "redteam", label: "Red Team" },
  { key: "review-source", label: "Source Review" },
];
const AGENTS = ["mainagent", "planner", "worker", "goals"];

// Mission Brains (M5): edit the per-mission Main/Planner/Worker/Goals system prompts. An
// empty box means that (mission, agent) has no stored brain and falls back to the built-in
// default. A task's mission then selects which of these brains runs.
export default function MissionBrainsPage() {
  const [data, setData] = React.useState<Record<string, Record<string, string>>>({});
  const [saving, setSaving] = React.useState<string>("");

  const load = React.useCallback(() => {
    api
      .missionPrompts()
      .then((r) => {
        const m: Record<string, Record<string, string>> = {};
        for (const p of r.prompts ?? []) {
          m[p.mission] = m[p.mission] ?? {};
          m[p.mission][p.agent_key] = p.body;
        }
        setData(m);
      })
      .catch(() => {});
  }, []);
  React.useEffect(load, [load]);

  const set = (mission: string, agent: string, v: string) =>
    setData((d) => ({ ...d, [mission]: { ...(d[mission] ?? {}), [agent]: v } }));

  const save = async (mission: string, agent: string) => {
    const key = `${mission}/${agent}`;
    setSaving(key);
    try {
      await api.saveMissionPrompt(mission, agent, data[mission]?.[agent] ?? "");
      toast.success(`Saved ${key}`);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setSaving("");
    }
  };

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-semibold">Mission Brains</h1>
        <p className="text-muted-foreground text-sm">
          Per-mission Main/Planner/Worker/Goals system prompts. A task&apos;s mission selects which brains run.
          Empty = fall back to the built-in default (bug-bounty / red-team keep the pentest defaults when empty).
        </p>
      </div>
      {MISSIONS.map((m) => (
        <Card key={m.key} className="p-4">
          <div className="mb-3 text-lg font-medium">{m.label} <span className="text-muted-foreground text-xs">({m.key})</span></div>
          <div className="grid gap-4 md:grid-cols-2">
            {AGENTS.map((a) => (
              <div key={a} className="grid gap-1">
                <div className="flex items-center justify-between">
                  <label className="text-sm font-medium capitalize">{a}</label>
                  <Button size="sm" variant="outline" disabled={saving === `${m.key}/${a}`} onClick={() => void save(m.key, a)}>
                    {saving === `${m.key}/${a}` ? "Saving…" : "Save"}
                  </Button>
                </div>
                <Textarea
                  className="min-h-32 font-mono text-xs"
                  placeholder={`${a} system prompt for ${m.label} (empty = built-in default)…`}
                  value={data[m.key]?.[a] ?? ""}
                  onChange={(e) => set(m.key, a, e.target.value)}
                />
              </div>
            ))}
          </div>
        </Card>
      ))}
    </div>
  );
}
