"use client";

import * as React from "react";
import dynamic from "next/dynamic";

const Client = dynamic(() => import("./upload-client"), {
  ssr: false,
  loading: () => <div className="text-muted-foreground p-6 text-sm">Loading…</div>,
});

export default function Page() {
  return (
    <React.Suspense fallback={<div className="text-muted-foreground p-6 text-sm">Loading…</div>}>
      <Client />
    </React.Suspense>
  );
}
