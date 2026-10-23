"use client";

import * as React from "react";
import dynamic from "next/dynamic";

const Client = dynamic(() => import("./rundetail-client"), {
  ssr: false,
  loading: () => <div className="text-muted-foreground p-6 text-sm">Loading…</div>,
});

export default function Page() {
  return (
    <React.Suspense fallback={<div className="text-muted-foreground p-6 text-sm">Loading…</div>}>
      <div className="h-[calc(100vh-var(--header-height,4rem))] min-h-0">
        <Client />
      </div>
    </React.Suspense>
  );
}
