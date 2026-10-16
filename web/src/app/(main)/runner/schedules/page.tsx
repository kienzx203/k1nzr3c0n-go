"use client";
import * as React from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { k1z } from "@/lib/k1z";
interface S { id: number; name: string; workflow: string; target: string; cron_expr: string; enabled?: boolean; next_run_at?: string }
export default function SchedulesPage() {
  const [items, setItems] = React.useState<S[]>([]);
  React.useEffect(() => { k1z.get("/schedules").then((r) => { const d = r as { items?: S[] } | S[]; setItems(Array.isArray(d) ? d : (d.items ?? [])); }).catch(() => {}); }, []);
  return (
    <div className="flex flex-col gap-4 p-4 md:p-6">
      <div><h1 className="text-xl font-semibold">Schedules</h1><p className="text-muted-foreground text-sm">Recurring workflow runs (cron).</p></div>
      <Card><CardContent className="p-0"><Table>
        <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Workflow</TableHead><TableHead>Target</TableHead><TableHead>Cron</TableHead><TableHead>Next</TableHead></TableRow></TableHeader>
        <TableBody>
          {items.map((s) => (<TableRow key={s.id}><TableCell>{s.name}</TableCell><TableCell className="font-mono text-xs">{s.workflow}</TableCell><TableCell className="font-mono">{s.target}</TableCell><TableCell className="font-mono text-xs">{s.cron_expr}</TableCell><TableCell className="text-muted-foreground text-xs">{(s.next_run_at ?? "").replace("T"," ").slice(0,16)}</TableCell></TableRow>))}
          {items.length === 0 && <TableRow><TableCell colSpan={5} className="text-muted-foreground py-8 text-center">No schedules.</TableCell></TableRow>}
        </TableBody>
      </Table></CardContent></Card>
    </div>
  );
}
