"use client";

// Route-level error boundary for Run Detail. Without it, a render-time exception
// in rundetail-client leaves a blank/black page. This surfaces the actual error
// (and a Retry) so failures are visible and debuggable instead of a black screen.
export default function RunDetailError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="p-8 text-sm">
      <div className="mb-2 font-semibold text-red-400">Failed to render this run.</div>
      <pre className="mb-3 max-w-3xl whitespace-pre-wrap break-words text-xs text-[var(--text-2)]">
        {error?.message || String(error)}
        {error?.stack ? "\n\n" + error.stack.split("\n").slice(0, 6).join("\n") : ""}
      </pre>
      <div className="flex gap-2">
        <button
          onClick={reset}
          className="rounded-md border border-[var(--surface-2)] px-3 py-1 text-xs hover:bg-[var(--bg-soft)]"
        >
          Retry
        </button>
        <a
          href="/runner/runs"
          className="rounded-md border border-[var(--surface-2)] px-3 py-1 text-xs hover:bg-[var(--bg-soft)]"
        >
          Back to Runs
        </a>
      </div>
    </div>
  );
}
