#!/usr/bin/env python3
"""
Agent A — Go driver.

    python3 agent_a/run_go.py <go_source_dir> [--db taint_spec.db]
                              [--cats SQLI,XSS,PATH,CMDI,SSRF,OPEN_REDIRECT]

Pipeline:  go_extract (go/ast) -> IR JSON -> engine.py (taint) -> findings.

Needs the Go toolchain on PATH (uses `go run` on the bundled extractor).
"""

import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import json as _json  # noqa: E402
import engine  # noqa: E402
from callgraph import CallGraph  # noqa: E402

DEFAULT_DB = os.path.join(ROOT, "taint_spec.db")
EXTRACTOR = os.path.join(HERE, "go_extract")
SSA_EXTRACTOR = os.path.join(HERE, "ssa_extract")
BIN_DIR = os.path.join(os.path.dirname(HERE), "bin")
GO_BIN = os.path.join(BIN_DIR, "go_extract")
SSA_BIN = os.path.join(BIN_DIR, "ssa_extract")
DEFAULT_CATS = ["SQLI", "NOSQLI", "XSS", "PATH", "CMDI", "ARG_INJECTION", "SSRF",
                "OPEN_REDIRECT", "CODE_INJECTION", "EL_INJECTION", "UNSAFE_REFLECTION",
                "LDAPI", "XPATHI", "XQUERYI", "XXE", "DESERIALIZATION", "CRLF",
                "HTTP_SPLITTING", "RFI_LFI", "UNRESTRICTED_UPLOAD", "LOG_INJECTION",
                "FORMAT_STRING", "RESOURCE_INJECTION", "IDOR", "CSRF"]

SEV_ICON = {"high": "🔴", "medium": "🟠", "needs-review": "🟡"}


def extract_ir(src_dir):
    out = subprocess.run(
        ([GO_BIN, os.path.abspath(src_dir)] if os.path.exists(GO_BIN) else ["go", "run", ".", os.path.abspath(src_dir)]),
        cwd=(None if os.path.exists(GO_BIN) else EXTRACTOR), capture_output=True, text=True)
    if out.stderr.strip():
        sys.stderr.write(out.stderr)
    if out.returncode != 0:
        # degrade gracefully (like run_lang): a Go-extractor failure must not abort the
        # whole single-target scan — return an empty-but-valid IR instead.
        sys.stderr.write(f"go extractor rc={out.returncode} (continuing)\n")
    try:
        ir = json.loads(out.stdout) if (out.stdout or "").strip() else {}
    except ValueError:
        ir = {}
    ir.setdefault("dir", src_dir)
    ir.setdefault("functions", [])
    ir.setdefault("call_seen", 0)
    ir.setdefault("call_total", 0)
    return ir


def _ensure_gomod(src_dir):
    """SSA/go.packages needs module mode. Synthesize a go.mod if missing so a
    loose set of .go files still loads; returns the created path (to remove), or
    None if one already existed."""
    gm = os.path.join(src_dir, "go.mod")
    if os.path.exists(gm):
        return None
    try:
        with open(gm, "w", encoding="utf-8") as fh:
            fh.write("module sastscan\n\ngo 1.21\n")
        return gm
    except OSError:
        return None


def extract_ssa(src_dir, timeout=300):
    """Precise SSA/VTA edges when the project builds; (None,None,False) on fallback.
    Returns (edges, algorithm, partial)."""
    src = os.path.abspath(src_dir)
    created = _ensure_gomod(src)
    try:
        out = subprocess.run(
            ([SSA_BIN, src] if os.path.exists(SSA_BIN) else ["go", "run", ".", src]),
            cwd=(None if os.path.exists(SSA_BIN) else SSA_EXTRACTOR), capture_output=True, text=True, timeout=timeout)
        if out.returncode != 0:
            return None, None, False
        data = json.loads(out.stdout or "{}")
        if not data.get("ok"):
            return None, None, False
        return data.get("edges", []), data.get("algorithm"), bool(data.get("partial"))
    except Exception:
        return None, None, False
    finally:
        if created and os.path.exists(created):
            try:
                os.remove(created)
            except OSError:
                pass


def build_graph(src_dir, ir):
    """Build the call graph, preferring SSA/VTA when the code builds."""
    ssa_edges, algo, partial = extract_ssa(src_dir)
    cg = CallGraph(ir, ssa_edges=ssa_edges)
    cg.ssa_algo = algo
    cg.ssa_partial = partial
    if algo:
        mode = "SSA/" + algo.upper() + (" (partial build)" if partial else " (precise)")
    else:
        mode = "AST heuristic (project did not build)"
    return cg, mode


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--cats", default=",".join(DEFAULT_CATS))
    ap.add_argument("--json", action="store_true", help="emit findings as JSON")
    ap.add_argument("--graph", metavar="PREFIX", nargs="?", const="callgraph",
                    help="write <PREFIX>.json and <PREFIX>.dot of the full call graph")
    ap.add_argument("--show-unresolved", action="store_true",
                    help="print the coverage ledger (unresolved / dynamic calls)")
    ap.add_argument("--summaries", action="store_true",
                    help="compute & print per-function summaries (scale model C)")
    args = ap.parse_args()
    cats = [c.strip().upper() for c in args.cats.split(",") if c.strip()]

    ir = extract_ir(args.src)
    cg, mode = build_graph(args.src, ir)
    spec = engine.load_spec(args.db, "go")
    az = engine.Analyzer(ir, spec, cg=cg)
    findings = az.run(cats)

    if args.graph:
        with open(args.graph + ".json", "w", encoding="utf-8") as fh:
            _json.dump(cg.to_dict(), fh, indent=2, ensure_ascii=False)
        with open(args.graph + ".dot", "w", encoding="utf-8") as fh:
            fh.write(cg.to_dot() + "\n")
        print(f"call graph written: {args.graph}.json, {args.graph}.dot "
              f"(render: dot -Tsvg {args.graph}.dot -o {args.graph}.svg)")

    if args.json:
        print(json.dumps(findings, indent=2, ensure_ascii=False))
        return

    st = cg.stats()
    print(f"\n╔═ Agent A — Go taint scan ═╗")
    print(f"  target     : {args.src}")
    print(f"  engine     : {mode}")
    print(f"  call graph : {st['functions']} functions, {st['edges']} internal edges "
          f"({st['resolved_by']}), {st['roots']} roots, {st['leaves']} leaves")
    print(f"  external   : {st['unresolved']} library/pkg call sites {st['unresolved_by']}")
    print(f"  taint-break: {st['taint_breaks']} unresolved USER/dynamic call(s) "
          f"(potential misses — see --show-unresolved)")
    print(f"  categories : {', '.join(cats)}")
    print(f"  findings   : {len(findings)}\n")

    if args.show_unresolved:
        print("  coverage ledger (unresolved call sites):")
        for u in cg.unresolved[:40]:
            print(f"    - {u['caller']}  →  {u['call']}  (line {u['line']}, {u['reason']})")
        print()

    if args.summaries:
        from summaries import SummaryEngine
        se = SummaryEngine(az, cats)
        summ, sfind = se.run()
        import json as _j
        print("  per-function summaries (model C):")
        print("  " + _j.dumps(se.dump(), ensure_ascii=False, indent=2).replace("\n", "\n  "))
        print(f"  summary-based findings: {len(sfind)}  (engine findings: {len(findings)})\n")

    if not findings:
        print("  (no tainted source→sink flow found)\n")
    for i, f in enumerate(findings, 1):
        icon = SEV_ICON.get(f["severity"], "•")
        flow = "  ⟶ inter-procedural" if f["interproc"] else ""
        print(f"{icon} [{i}] {f['category']}  ({f['severity']}, conf={f['confidence']}){flow}")
        print(f"     sink   : {f['sink']}()  — {f['sink_note']}")
        print(f"     where  : {os.path.relpath(f['pos']) if os.path.exists(f['pos'].split(':')[0]) else f['pos']}  (func {f['func']}, line {f['line']})")
        print(f"     source : {f['source']}")
        if f["weak_sanitizer"]:
            print(f"     note   : only a WEAK sanitizer on path → verify manually")
        print()


if __name__ == "__main__":
    main()
