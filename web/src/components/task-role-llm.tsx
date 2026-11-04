"use client";

import * as React from "react";

import { CpuIcon } from "lucide-react";
import { toast } from "sonner";

import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api } from "@/lib/api";
import type { LLMProfile } from "@/lib/types";

const ROLES: { key: string; label: string; hint: string }[] = [
  { key: "mainagent", label: "Main agent", hint: "Điều phối chính / chat" },
  { key: "planner", label: "Planner", hint: "Lập kế hoạch, sinh intent" },
  { key: "worker", label: "Worker", hint: "Thực thi từng intent" },
];

const DEFAULT_VALUE = "__default__";

export type RoleOverrides = Record<string, number | null>;

type Props = {
  profiles: LLMProfile[];
  disabled?: boolean;
  /** Self-managed mode: fetch + auto-save against this task. */
  taskId?: string;
  /** Controlled mode (e.g. the new-task form, before a task exists). */
  value?: RoleOverrides;
  onChange?: (next: RoleOverrides) => void;
  /** Render the Select dropdown inside this container (e.g. the popover) so a click
   *  doesn't register as an outside interaction. */
  portalContainer?: React.RefObject<HTMLElement | null>;
};

/**
 * Per-role LLM model override. Each role (main agent / planner / worker) can be
 * pinned to its own profile; an unset role follows the task chain / global binding.
 * Highest precedence in the resolver, effective on the role's next LLM call.
 *
 * With `taskId` it fetches + auto-saves; with `value`/`onChange` it is a controlled
 * field (used in the new-task form, which applies the overrides after the task is created).
 */
export function TaskRoleLLM({ profiles, disabled, taskId, value, onChange, portalContainer }: Props) {
  const labelOf = (role: string) => ROLES.find((r) => r.key === role)?.label ?? role;
  const modelOf = (pid: number | null) =>
    pid == null ? "Mặc định" : (profiles.find((p) => String(p.id) === String(pid))?.name ?? `#${pid}`);
  const selfManaged = Boolean(taskId);
  const [fetched, setFetched] = React.useState<Record<string, number>>({});
  const [savingRole, setSavingRole] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (!taskId) return;
    let alive = true;
    api
      .getTaskRoleLLM(taskId)
      .then((r) => alive && setFetched(r ?? {}))
      .catch(() => alive && setFetched({}));
    return () => {
      alive = false;
    };
  }, [taskId]);

  const current: RoleOverrides = selfManaged ? fetched : (value ?? {});

  const setRole = async (role: string, next: number | null) => {
    if (selfManaged && taskId) {
      setSavingRole(role);
      setError(null);
      try {
        const result = await api.updateTaskRoleLLM(taskId, { [role]: next });
        setFetched(result ?? {});
        toast.success(`${labelOf(role)} → ${modelOf(next)}`);
      } catch (e) {
        const msg = e instanceof Error ? e.message : "Lưu thất bại";
        setError(msg);
        toast.error(`Lưu model cho ${labelOf(role)} thất bại: ${msg}`);
      } finally {
        setSavingRole(null);
      }
    } else {
      onChange?.({ ...(value ?? {}), [role]: next });
    }
  };

  return (
    <div className="space-y-3 rounded-lg border bg-muted/20 p-3">
      <div className="flex items-start gap-2">
        <CpuIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
        <div className="space-y-0.5">
          <div className="font-medium text-sm leading-none">Model theo vai trò</div>
          <p className="text-muted-foreground text-xs leading-snug">
            Mỗi vai trò chạy model riêng. <span className="font-medium">Mặc định</span> = theo chain/global. Ghi đè ưu
            tiên cao nhất, hiệu lực ở lần gọi LLM kế tiếp.
          </p>
        </div>
      </div>

      <div className="space-y-1.5">
        {ROLES.map(({ key, label, hint }) => {
          const selected = current[key];
          const triggerValue = selected ? String(selected) : DEFAULT_VALUE;
          return (
            <div
              key={key}
              className="grid grid-cols-[minmax(0,1fr)_minmax(0,1.6fr)] items-center gap-3 rounded-md px-1 py-1"
            >
              <div className="min-w-0">
                <div className="truncate font-medium text-sm">{label}</div>
                <div className="truncate text-muted-foreground text-[11px] leading-tight">{hint}</div>
              </div>
              <Select
                value={triggerValue}
                onValueChange={(v) => setRole(key, v === DEFAULT_VALUE ? null : Number(v))}
                disabled={disabled || savingRole === key}
              >
                <SelectTrigger size="sm" className="w-full" aria-label={`Model cho ${label}`}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent container={portalContainer?.current ?? undefined}>
                  <SelectGroup>
                    <SelectItem value={DEFAULT_VALUE}>
                      <span className="text-muted-foreground">Mặc định</span>
                    </SelectItem>
                    {profiles.map((p) => (
                      <SelectItem key={p.id} value={String(p.id)}>
                        <span className="flex min-w-0 items-center gap-1.5">
                          <span className="truncate font-medium">{p.name}</span>
                          <span className="truncate text-muted-foreground text-xs">{p.model}</span>
                        </span>
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            </div>
          );
        })}
      </div>

      {error && <p className="text-destructive text-xs">{error}</p>}
    </div>
  );
}
