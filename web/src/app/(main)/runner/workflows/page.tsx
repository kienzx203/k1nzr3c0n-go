"use client";
import * as React from "react";
import Link from "next/link";
import { PencilIcon, PlusIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { k1z } from "@/lib/k1z";

interface Wf {
  name: string;
  steps?: number;
  desc?: string;
  tags?: string[];
}

export default function WorkflowsPage() {
  const [items, setItems] = React.useState<Wf[]>([]);
  React.useEffect(() => {
    k1z
      .get("/workflows")
      .then((r) => setItems((r as { workflows?: Wf[] }).workflows ?? []))
      .catch(() => {});
  }, []);
  return (
    <div className="flex flex-col gap-4 p-4 md:p-6">
      <div className="flex items-start justify-between gap-2">
        <div>
          <h1 className="text-xl font-semibold">Workflows</h1>
          <p className="text-muted-foreground text-sm">YAML recon pipelines available to the runner.</p>
        </div>
        <Link href="/runner/editor">
          <Button>
            <PlusIcon className="size-4" /> New workflow
          </Button>
        </Link>
      </div>
      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Steps</TableHead>
                <TableHead>Description</TableHead>
                <TableHead className="w-20 text-right">Edit</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((w) => (
                <TableRow key={w.name}>
                  <TableCell className="font-mono">{w.name}</TableCell>
                  <TableCell>{w.steps ?? "-"}</TableCell>
                  <TableCell className="text-muted-foreground max-w-[520px] truncate">{w.desc}</TableCell>
                  <TableCell className="text-right">
                    <Link href={`/runner/editor?name=${encodeURIComponent(w.name)}`}>
                      <Button size="sm" variant="ghost">
                        <PencilIcon className="size-3.5" />
                      </Button>
                    </Link>
                  </TableCell>
                </TableRow>
              ))}
              {items.length === 0 && (
                <TableRow>
                  <TableCell colSpan={4} className="text-muted-foreground py-8 text-center">
                    No workflows found.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
