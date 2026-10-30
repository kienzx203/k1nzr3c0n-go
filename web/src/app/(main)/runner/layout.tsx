import type { ReactNode } from "react";

import "./runner-legacy.css";

// The ported k1nzr3c0n runner pages use the original dark console design system
// (CSS vars + .btn/.input/.card/.table-base/.badge helpers). Scope it to the
// runner section so it doesn't leak into the rest of the ScopeWeaver shell.
export default function RunnerLayout({ children }: { children: ReactNode }) {
  // h-full is required so a page that lays itself out as `flex flex-col h-full`
  // (the run-detail view) gets a viewport-bounded height and scrolls its log pane
  // INTERNALLY. Without it, .k1z-legacy was height:auto, that page's h-full
  // collapsed to content height, the log pane never clipped, and the whole page
  // grew tall — so auto-scroll dragged the header/tabs off the top. Natural-flow
  // runner pages (no h-full) are unaffected: they overflow and page-scroll as before.
  return <div className="k1z-legacy h-full min-h-0">{children}</div>;
}
