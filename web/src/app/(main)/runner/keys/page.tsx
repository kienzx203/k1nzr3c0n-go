"use client";
import * as React from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { k1z } from "@/lib/k1z";
interface Key { provider: string; value_masked?: string; updated_at?: string }
export default function KeysPage() {
  const [keys, setKeys] = React.useState<Key[]>([]);
  const [provider, setProvider] = React.useState("");
  const [value, setValue] = React.useState("");
  const load = React.useCallback(() => { k1z.get("/keys").then((r) => { const d = r as { items?: Key[] } | Key[]; setKeys(Array.isArray(d) ? d : (d.items ?? [])); }).catch(() => {}); }, []);
  React.useEffect(() => { load(); }, [load]);
  async function save() { if (!provider.trim() || !value.trim()) return; try { await k1z.put(`/keys/${encodeURIComponent(provider.trim())}`, { value: value.trim() }); } catch { /* */ } finally { setValue(""); load(); } }
  async function del(p: string) { try { await k1z.del(`/keys/${encodeURIComponent(p)}`); load(); } catch { /* */ } }
  return (
    <div className="flex flex-col gap-4 p-4 md:p-6">
      <div><h1 className="text-xl font-semibold">API Keys</h1><p className="text-muted-foreground text-sm">Provider keys used by recon tools (subfinder, etc.).</p></div>
      <Card><CardContent className="flex flex-wrap items-end gap-2 p-4">
        <div className="flex flex-col gap-1"><label className="text-muted-foreground text-xs">Provider</label><Input value={provider} placeholder="shodan" onChange={(e) => setProvider(e.target.value)} /></div>
        <div className="flex min-w-[260px] flex-1 flex-col gap-1"><label className="text-muted-foreground text-xs">Key</label><Input type="password" value={value} onChange={(e) => setValue(e.target.value)} /></div>
        <Button onClick={save}>Save key</Button>
      </CardContent></Card>
      <Card><CardContent className="p-0"><Table>
        <TableHeader><TableRow><TableHead>Provider</TableHead><TableHead>Value</TableHead><TableHead>Updated</TableHead><TableHead></TableHead></TableRow></TableHeader>
        <TableBody>
          {keys.map((k) => (<TableRow key={k.provider}><TableCell className="font-mono">{k.provider}</TableCell><TableCell className="text-muted-foreground font-mono text-xs">{k.value_masked}</TableCell><TableCell className="text-muted-foreground text-xs">{(k.updated_at ?? "").replace("T"," ").slice(0,16)}</TableCell><TableCell><Button variant="outline" size="sm" onClick={() => del(k.provider)}>Delete</Button></TableCell></TableRow>))}
          {keys.length === 0 && <TableRow><TableCell colSpan={4} className="text-muted-foreground py-8 text-center">No keys set.</TableCell></TableRow>}
        </TableBody>
      </Table></CardContent></Card>
    </div>
  );
}
