"use client";

import * as React from "react";
import dynamic from "next/dynamic";

import "./editor.css";

// React Flow + the visual editor touch the DOM, so keep them out of the
// static-export prerender.
const EditorClient = dynamic(() => import("./editor-client"), {
  ssr: false,
  loading: () => <div className="text-muted-foreground p-6 text-sm">Loading workflow editor…</div>,
});

export default function WorkflowEditorPage() {
  return (
    <React.Suspense fallback={<div className="text-muted-foreground p-6 text-sm">Loading…</div>}>
      <div className="k1z-editor-scope h-[calc(100vh-var(--header-height,4rem))] min-h-0">
        <EditorClient />
      </div>
    </React.Suspense>
  );
}
