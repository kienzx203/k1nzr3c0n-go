"use client";

import * as React from "react";
import { FileUpIcon, Trash2Icon, CheckIcon, XIcon, Loader2Icon } from "lucide-react";

import { Card, CardContent } from "@/components/ui/card";

// Upload uses multipart/form-data, which the JSON k1z helper can't send, so we
// hand-roll the fetch here and attach the same bearer token it would.
function authToken(): string {
  try {
    return (typeof window !== "undefined" && localStorage.getItem("artex_token")) || "";
  } catch {
    return "";
  }
}

async function apiGet(path: string): Promise<Response> {
  const t = authToken();
  return fetch(`/api/v1${path}`, { headers: t ? { Authorization: `Bearer ${t}` } : {} });
}

async function apiDelete(path: string): Promise<void> {
  const t = authToken();
  await fetch(`/api/v1${path}`, { method: "DELETE", headers: t ? { Authorization: `Bearer ${t}` } : {} });
}

async function apiUpload(path: string, file: File): Promise<void> {
  const t = authToken();
  const fd = new FormData();
  fd.append("file", file);
  const r = await fetch(`/api/v1${path}`, {
    method: "POST",
    headers: t ? { Authorization: `Bearer ${t}` } : {},
    body: fd,
  });
  if (!r.ok) {
    let detail = r.statusText;
    try {
      detail = ((await r.json()) as { detail?: string }).detail ?? detail;
    } catch {
      /* ignore */
    }
    throw new Error(detail);
  }
}

function fmtSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
}

interface UploadRow {
  name: string;
  status: "loading" | "done" | "error";
  error?: string;
}

interface FileEntry {
  name: string;
  size: number;
}

function DropZone({
  accept,
  label,
  hint,
  onFiles,
}: {
  accept: string;
  label: string;
  hint: string;
  onFiles: (files: File[]) => void;
}) {
  const [over, setOver] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement>(null);

  return (
    <div
      onClick={() => inputRef.current?.click()}
      onDragOver={(e) => {
        e.preventDefault();
        setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        setOver(false);
        if (e.dataTransfer.files?.length) onFiles(Array.from(e.dataTransfer.files));
      }}
      className={`relative cursor-pointer rounded-lg border-2 border-dashed px-6 py-10 text-center transition-colors ${
        over ? "border-primary bg-primary/5" : "border-input hover:border-primary/50 hover:bg-muted/50"
      }`}
    >
      <input
        ref={inputRef}
        type="file"
        accept={accept}
        multiple
        className="hidden"
        onChange={(e) => {
          if (e.target.files?.length) onFiles(Array.from(e.target.files));
          e.target.value = "";
        }}
      />
      <FileUpIcon className="text-muted-foreground mx-auto mb-2 size-7" />
      <p className="text-sm font-medium">{label}</p>
      <p className="text-muted-foreground mt-1 text-xs">{hint}</p>
    </div>
  );
}

function UploadFeedback({ rows }: { rows: UploadRow[] }) {
  if (rows.length === 0) return null;
  return (
    <div className="space-y-0.5">
      {rows.map((u, i) => (
        <div
          key={i}
          className={`flex items-center gap-2 rounded px-2 py-1 font-mono text-xs ${
            u.status === "done"
              ? "text-green-600"
              : u.status === "error"
                ? "text-red-600"
                : "text-amber-600"
          }`}
        >
          {u.status === "loading" ? (
            <Loader2Icon className="size-3 animate-spin" />
          ) : u.status === "done" ? (
            <CheckIcon className="size-3" />
          ) : (
            <XIcon className="size-3" />
          )}
          <span className="flex-1 truncate">{u.name}</span>
          {u.error && <span className="text-[10px] opacity-75">{u.error}</span>}
        </div>
      ))}
    </div>
  );
}

function FileList({
  loading,
  files,
  empty,
  onDelete,
}: {
  loading: boolean;
  files: FileEntry[];
  empty: string;
  onDelete: (name: string) => void;
}) {
  if (loading) return <p className="text-muted-foreground px-3 text-xs">Loading…</p>;
  if (files.length === 0) return <p className="text-muted-foreground px-3 text-xs">{empty}</p>;
  return (
    <div className="divide-border border-border divide-y rounded border">
      {files.map((f) => (
        <div key={f.name} className="hover:bg-muted/50 group flex items-center gap-2 px-3 py-2 transition-colors">
          <span className="flex-1 truncate font-mono text-xs">{f.name}</span>
          <span className="text-muted-foreground flex-shrink-0 text-[10px]">{fmtSize(f.size)}</span>
          <button
            onClick={() => onDelete(f.name)}
            title="Delete"
            className="flex-shrink-0 rounded p-1 text-red-600 opacity-0 transition-all hover:bg-red-500/10 group-hover:opacity-100"
          >
            <Trash2Icon className="size-3.5" />
          </button>
        </div>
      ))}
    </div>
  );
}

function Section({
  title,
  badge,
  children,
}: {
  title: string;
  badge: number;
  children: React.ReactNode;
}) {
  return (
    <Card>
      <CardContent className="p-0">
        <div className="border-border flex items-center gap-2 border-b px-4 py-3">
          <span className="text-sm font-semibold">{title}</span>
          <span className="bg-muted text-muted-foreground ml-auto rounded-full px-2 py-0.5 text-xs">{badge}</span>
        </div>
        <div className="space-y-4 p-4">{children}</div>
      </CardContent>
    </Card>
  );
}

export default function UploadPage() {
  const [wordlists, setWordlists] = React.useState<FileEntry[]>([]);
  const [workflows, setWorkflows] = React.useState<FileEntry[]>([]);
  const [wlUploads, setWlUploads] = React.useState<UploadRow[]>([]);
  const [wfUploads, setWfUploads] = React.useState<UploadRow[]>([]);
  const [loadingWl, setLoadingWl] = React.useState(true);
  const [loadingWf, setLoadingWf] = React.useState(true);

  const fetchWordlists = React.useCallback(async () => {
    setLoadingWl(true);
    try {
      const r = await apiGet("/wordlists");
      if (r.ok) {
        const data = (await r.json()) as FileEntry[] | { items?: FileEntry[] };
        setWordlists(Array.isArray(data) ? data : (data.items ?? []));
      }
    } catch {
      /* ignore */
    } finally {
      setLoadingWl(false);
    }
  }, []);

  const fetchWorkflows = React.useCallback(async () => {
    setLoadingWf(true);
    try {
      const r = await apiGet("/workflows");
      if (r.ok) {
        const raw = (await r.json()) as unknown;
        // backend returns either ["name",...] or {workflows:[{name}]}
        let names: string[] = [];
        if (Array.isArray(raw)) {
          names = raw.map((x) => (typeof x === "string" ? x : (x as { name?: string }).name ?? "")).filter(Boolean);
        } else {
          const list = (raw as { workflows?: { name: string }[] }).workflows ?? [];
          names = list.map((x) => x.name).filter(Boolean);
        }
        const items = await Promise.all(
          names.map(async (name) => {
            try {
              const r2 = await apiGet(`/workflows/${encodeURIComponent(name)}`);
              const text = r2.ok ? await r2.text() : "";
              return { name, size: new TextEncoder().encode(text).length };
            } catch {
              return { name, size: 0 };
            }
          }),
        );
        setWorkflows(items);
      }
    } catch {
      /* ignore */
    } finally {
      setLoadingWf(false);
    }
  }, []);

  React.useEffect(() => {
    fetchWordlists();
    fetchWorkflows();
  }, [fetchWordlists, fetchWorkflows]);

  const upload = React.useCallback(
    async (
      files: File[],
      endpoint: string,
      setRows: React.Dispatch<React.SetStateAction<UploadRow[]>>,
      refresh: () => void,
    ) => {
      setRows((prev) => [...prev, ...files.map((f): UploadRow => ({ name: f.name, status: "loading" }))]);
      await Promise.all(
        files.map(async (file) => {
          try {
            await apiUpload(endpoint, file);
            setRows((prev) =>
              prev.map((row) =>
                row.name === file.name && row.status === "loading" ? { ...row, status: "done" } : row,
              ),
            );
          } catch (err) {
            setRows((prev) =>
              prev.map((row) =>
                row.name === file.name && row.status === "loading"
                  ? { ...row, status: "error", error: (err as Error).message }
                  : row,
              ),
            );
          }
        }),
      );
      refresh();
    },
    [],
  );

  return (
    <div className="mx-auto flex w-full max-w-4xl flex-col gap-6 p-4 md:p-6">
      <div>
        <h1 className="text-xl font-semibold">Upload</h1>
        <p className="text-muted-foreground text-sm">
          Wordlists are saved under <code className="text-primary">wordlists/</code> and workflows under{" "}
          <code className="text-primary">workflows/</code> — reference them directly in workflow vars.
        </p>
      </div>

      <Section title="Wordlists" badge={wordlists.length}>
        <DropZone
          accept=".txt"
          label="Drop .txt wordlist files here"
          hint="Subdomain / directory / parameter wordlists — any .txt file"
          onFiles={(files) => upload(files, "/wordlists", setWlUploads, fetchWordlists)}
        />
        <UploadFeedback rows={wlUploads} />
        <FileList
          loading={loadingWl}
          files={wordlists}
          empty="No wordlists uploaded yet"
          onDelete={async (name) => {
            await apiDelete(`/wordlists/${encodeURIComponent(name)}`);
            fetchWordlists();
          }}
        />
      </Section>

      <Section title="Workflows" badge={workflows.length}>
        <DropZone
          accept=".yaml,.yml"
          label="Drop .yaml workflow files here"
          hint="Custom workflow YAML files"
          onFiles={(files) => upload(files, "/upload/workflow", setWfUploads, fetchWorkflows)}
        />
        <UploadFeedback rows={wfUploads} />
        <FileList
          loading={loadingWf}
          files={workflows}
          empty="No workflows found"
          onDelete={async (name) => {
            await apiDelete(`/workflows/${encodeURIComponent(name)}`);
            fetchWorkflows();
          }}
        />
      </Section>
    </div>
  );
}
