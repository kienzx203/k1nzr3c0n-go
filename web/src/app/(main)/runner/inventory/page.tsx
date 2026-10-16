"use client";
import * as React from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { k1z } from "@/lib/k1z";
interface A { host?: string; ip?: string; port?: number; title?: string; tech?: string[]; status_code?: number }
export default function InventoryPage() {
  const [items, setItems] = React.useState<A[]>([]);
  React.useEffect(() => { k1z.get("/assets").then((r) => setItems(((r as { items?: A[] }).items) ?? [])).catch(() => {}); }, []);
  return (
    <div className="flex flex-col gap-4 p-4 md:p-6">
      <div><h1 className="text-xl font-semibold">Inventory</h1><p className="text-muted-foreground text-sm">Cross-run deduplicated HTTP assets.</p></div>
      <Card><CardContent className="p-0"><Table>
        <TableHeader><TableRow><TableHead>Host</TableHead><TableHead>IP</TableHead><TableHead>Port</TableHead><TableHead>Code</TableHead><TableHead>Title</TableHead></TableRow></TableHeader>
        <TableBody>
          {items.map((a, i) => (<TableRow key={i}><TableCell className="font-mono">{a.host}</TableCell><TableCell className="font-mono text-xs">{a.ip}</TableCell><TableCell>{a.port}</TableCell><TableCell>{a.status_code}</TableCell><TableCell className="text-muted-foreground max-w-[360px] truncate">{a.title}</TableCell></TableRow>))}
          {items.length === 0 && <TableRow><TableCell colSpan={5} className="text-muted-foreground py-8 text-center">No assets yet.</TableCell></TableRow>}
        </TableBody>
      </Table></CardContent></Card>
    </div>
  );
}
