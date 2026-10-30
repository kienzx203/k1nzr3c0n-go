import type { ReactNode } from "react";

import "./runner-legacy.css";

// The ported k1nzr3c0n runner pages use the original dark console design system
// (CSS vars + .btn/.input/.card/.table-base/.badge helpers). Scope it to the
// runner section so it doesn't leak into the rest of the ScopeWeaver shell.
export default function RunnerLayout({ children }: { children: ReactNode }) {
  return <div className="k1z-legacy">{children}</div>;
}
