"use client";
import * as React from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { k1z } from "@/lib/k1z";
interface T { name: string; mode?: string; scope_json?: string }
export default function TargetsPage() {
  const [items, setItems] = React.useState<T[]>([]);
  const [name, setName] = React.useState("");
  const load = React.useCallback(() => { k1z.get("/targets").then((r) => { const d = r as { items?: T[]; targets?: T[] }; setItems(d.items ?? d.targets ?? []); }).catch(() => {}); }, []);
  React.useEffect(() => { load(); }, [load]);
  async function add() { if (!name.trim()) return; try { await k1z.post("/targets", { name: name.trim(), scope: [name.trim()] }); setName(""); load(); } catch { /* */ } }
  return (
    <div className="flex flex-col gap-4 p-4 md:p-6">
      <div><h1 className="text-xl font-semibold">Targets</h1><p className="text-muted-foreground text-sm">Registered targets and their scope.</p></div>
      <Card><CardContent className="flex items-end gap-2 p-4"><div className="flex flex-1 flex-col gap-1"><label className="text-muted-foreground text-xs">New target</label><Input value={name} placeholder="example.com" onChange={(e) => setName(e.target.value)} /></div><Button onClick={add}>Add target</Button></CardContent></Card>
      <Card><CardContent className="p-0"><Table>
        <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Mode</TableHead><TableHead>Scope</TableHead></TableRow></TableHeader>
        <TableBody>
          {items.map((t) => (<TableRow key={t.name}><TableCell className="font-mono">{t.name}</TableCell><TableCell>{t.mode}</TableCell><TableCell className="text-muted-foreground font-mono text-xs max-w-[480px] truncate">{t.scope_json}</TableCell></TableRow>))}
          {items.length === 0 && <TableRow><TableCell colSpan={3} className="text-muted-foreground py-8 text-center">No targets yet.</TableCell></TableRow>}
        </TableBody>
      </Table></CardContent></Card>
    </div>
  );
}
