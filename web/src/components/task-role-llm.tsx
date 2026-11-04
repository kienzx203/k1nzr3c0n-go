"use client";

import * as React from "react";

import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api } from "@/lib/api";
import type { LLMProfile } from "@/lib/types";

const ROLES: { key: string; label: string }[] = [
  { key: "mainagent", label: "Main agent" },
  { key: "planner", label: "Planner" },
  { key: "worker", label: "Worker" },
];

const NONE = "none";

type Props = {
  taskId: string;
  profiles: LLMProfile[];
  disabled?: boolean;
};

/**
 * Per-role LLM model override for a single task. Each role (main agent / planner /
 * worker) can be pinned to its own profile; an unset role follows the task chain /
 * global binding. Highest precedence in the server resolver. Saves on change and
 * takes effect on the role's next LLM call.
 */
export function TaskRoleLLM({ taskId, profiles, disabled }: Props) {
  const [overrides, setOverrides] = React.useState<Record<string, number>>({});
  const [savingRole, setSavingRole] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    let alive = true;
    api
      .getTaskRoleLLM(taskId)
      .then((r) => alive && setOverrides(r ?? {}))
      .catch(() => alive && setOverrides({}));
    return () => {
      alive = false;
    };
  }, [taskId]);

  const onChange = async (role: string, value: string) => {
    const next = value === NONE ? null : Number(value);
    setSavingRole(role);
    setError(null);
    try {
      const result = await api.updateTaskRoleLLM(taskId, { [role]: next });
      setOverrides(result ?? {});
    } catch (e) {
      setError(e instanceof Error ? e.message : "save failed");
    } finally {
      setSavingRole(null);
    }
  };

  return (
    <div className="space-y-2 rounded-md border p-3">
      <div className="font-medium text-sm">Model theo vai trò (ghi đè cho task này)</div>
      <p className="text-muted-foreground text-xs">
        Mỗi vai trò chạy model riêng; để trống = theo chain/global. Ưu tiên cao nhất, áp dụng ở lần gọi LLM kế tiếp.
      </p>
      {ROLES.map(({ key, label }) => {
        const current = overrides[key] ? String(overrides[key]) : NONE;
        return (
          <div key={key} className="flex items-center justify-between gap-2">
            <span className="text-sm">{label}</span>
            <Select
              value={current}
              onValueChange={(v) => onChange(key, v)}
              disabled={disabled || savingRole === key}
            >
              <SelectTrigger size="sm" className="w-56">
                <SelectValue placeholder="(theo chain/global)" />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value={NONE}>(theo chain/global)</SelectItem>
                  {profiles.map((p) => (
                    <SelectItem key={p.id} value={String(p.id)}>
                      {p.name} · {p.model}
                    </SelectItem>
                  ))}
                </SelectGroup>
              </SelectContent>
            </Select>
          </div>
        );
      })}
      {error && <p className="text-destructive text-xs">{error}</p>}
    </div>
  );
}
