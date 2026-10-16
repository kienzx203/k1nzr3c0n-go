"use client";
import * as React from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { k1z } from "@/lib/k1z";
interface Tool { name: string; installed?: string | null; latest?: string | null; status?: string; outdated?: boolean }
export default function ToolsPage() {
  const [items, setItems] = React.useState<Tool[]>([]);
  const [checking, setChecking] = React.useState(false);
  const load = React.useCallback(() => { k1z.get("/tools").then((r) => setItems(((r as { tools?: Tool[] }).tools) ?? [])).catch(() => {}); }, []);
  React.useEffect(() => { load(); }, [load]);
  async function check() { setChecking(true); try { await k1z.post("/tools/check"); load(); } catch { /* */ } finally { setChecking(false); } }
  return (
    <div className="flex flex-col gap-4 p-4 md:p-6">
      <div className="flex items-center"><div><h1 className="text-xl font-semibold">Tool versions</h1><p className="text-muted-foreground text-sm">Installed recon tools and available updates.</p></div><Button className="ml-auto" variant="outline" onClick={check} disabled={checking}>{checking ? "Checking…" : "Check versions"}</Button></div>
      <Card><CardContent className="p-0"><Table>
        <TableHeader><TableRow><TableHead>Tool</TableHead><TableHead>Installed</TableHead><TableHead>Latest</TableHead><TableHead>Status</TableHead></TableRow></TableHeader>
        <TableBody>
          {items.map((t) => (<TableRow key={t.name}><TableCell className="font-mono">{t.name}</TableCell><TableCell className="font-mono text-xs">{t.installed ?? "-"}</TableCell><TableCell className="font-mono text-xs">{t.latest ?? "-"}</TableCell><TableCell className={t.outdated ? "text-amber-600" : "text-muted-foreground"}>{t.outdated ? "outdated" : (t.status ?? "")}</TableCell></TableRow>))}
          {items.length === 0 && <TableRow><TableCell colSpan={4} className="text-muted-foreground py-8 text-center">Loading tools…</TableCell></TableRow>}
        </TableBody>
      </Table></CardContent></Card>
    </div>
  );
}
