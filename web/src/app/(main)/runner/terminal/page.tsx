"use client";

import dynamic from "next/dynamic";

// xterm touches the DOM, so it must never run during the static-export prerender.
const TerminalClient = dynamic(() => import("./terminal-client"), {
  ssr: false,
  loading: () => <div className="text-muted-foreground p-6 text-sm">Loading terminal…</div>,
});

export default function TerminalPage() {
  return <TerminalClient />;
}
