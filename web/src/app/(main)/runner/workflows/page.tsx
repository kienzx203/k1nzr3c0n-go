"use client";
import * as React from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { k1z } from "@/lib/k1z";
interface Wf { name: string; steps?: number; desc?: string; tags?: string[] }
export default function WorkflowsPage() {
  const [items, setItems] = React.useState<Wf[]>([]);
  React.useEffect(() => { k1z.get("/workflows").then((r) => setItems(((r as { workflows?: Wf[] }).workflows) ?? [])).catch(() => {}); }, []);
  return (
    <div className="flex flex-col gap-4 p-4 md:p-6">
      <div><h1 className="text-xl font-semibold">Workflows</h1><p className="text-muted-foreground text-sm">YAML recon pipelines available to the runner.</p></div>
      <Card><CardContent className="p-0"><Table>
        <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Steps</TableHead><TableHead>Description</TableHead></TableRow></TableHeader>
        <TableBody>
          {items.map((w) => (<TableRow key={w.name}><TableCell className="font-mono">{w.name}</TableCell><TableCell>{w.steps ?? "-"}</TableCell><TableCell className="text-muted-foreground max-w-[520px] truncate">{w.desc}</TableCell></TableRow>))}
          {items.length === 0 && <TableRow><TableCell colSpan={3} className="text-muted-foreground py-8 text-center">No workflows found.</TableCell></TableRow>}
        </TableBody>
      </Table></CardContent></Card>
    </div>
  );
}
