// Client helper for k1nzr3c0n's workflow-runner backend, mounted at /api/v1/*.
function token(): string {
  try {
    return (typeof window !== "undefined" && localStorage.getItem("artex_token")) || "";
  } catch {
    return "";
  }
}

async function call(method: string, path: string, body?: unknown): Promise<unknown> {
  const t = token();
  const r = await fetch(`/api/v1${path}`, {
    method,
    headers: {
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(t ? { Authorization: `Bearer ${t}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
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
  if (r.status === 204) return null;
  return r.json();
}

export const k1z = {
  get: (path: string) => call("GET", path),
  post: (path: string, body?: unknown) => call("POST", path, body),
  patch: (path: string, body?: unknown) => call("PATCH", path, body),
  del: (path: string) => call("DELETE", path),
};
