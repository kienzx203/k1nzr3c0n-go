#!/usr/bin/env python3
"""
Agent A — generic multi-language driver (tree-sitter frontends).

    python3 agent_a/run_lang.py <lang> <dir> [--db taint_spec.db] [--cats ...] [--json]

Pipeline: ts_extract/extract.py (tree-sitter -> IR) -> callgraph.py -> engine.py.
Go uses run_go.py (go/ast + SSA/VTA); every other language uses this.
"""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import engine            # noqa: E402
from callgraph import CallGraph  # noqa: E402

TS = os.path.join(HERE, "ts_extract")
DEFAULT_DB = os.path.join(ROOT, "taint_spec.db")

# lang (tree-sitter / plugin name) -> taint_spec family
LANG_FAMILY = {
    "python": "python", "java": "java", "javascript": "javascript",
    "typescript": "javascript", "php": "php", "csharp": "dotnet",
    "ruby": "ruby", "kotlin": "kotlin", "cpp": "cpp",
    "swift": "swift", "rust": "rust", "go": "go",
    "perl": "perl", "objc": "objc", "vbnet": "dotnet",
    "plsql": "plsql", "vb6": "dotnet", "cobol": "cobol",
}
DEFAULT_CATS = ["SQLI", "NOSQLI", "INJECTION", "XSS", "PATH", "CMDI",
                "ARG_INJECTION", "SSRF", "OPEN_REDIRECT", "CODE_INJECTION",
                "EL_INJECTION", "UNSAFE_REFLECTION", "LDAPI", "XPATHI",
                "XQUERYI", "XXE", "DESERIALIZATION", "CRLF", "HTTP_SPLITTING",
                "RFI_LFI", "UNRESTRICTED_UPLOAD", "LOG_INJECTION",
                "FORMAT_STRING", "RESOURCE_INJECTION", "IDOR", "PARAM_TAMPERING",
                "TRUST_BOUNDARY", "CSRF"]
SEV_ICON = {"high": "🔴", "medium": "🟠", "needs-review": "🟡"}


def extract_ir(lang, src_dir):
    # languages without a usable tree-sitter grammar use the lightweight
    # structural extractor (same IR): PL/SQL, VB6/VBScript, COBOL.
    import line_extract
    if lang in line_extract.EXTRACTORS:
        return _dedup_keys(line_extract.extract_ir(lang, src_dir))
    out = subprocess.run([sys.executable, "extract.py", lang, os.path.abspath(src_dir)],
                         cwd=TS, capture_output=True, text=True)
    if out.stderr.strip():
        sys.stderr.write(out.stderr)
    if out.returncode != 0:
        # degrade gracefully: a sub-extractor crash must not kill the whole scan —
        # salvage any JSON already emitted, else return an empty-but-valid IR.
        sys.stderr.write(f"ts extractor rc={out.returncode} for {lang} (continuing)\n")
    try:
        ir = json.loads(out.stdout) if (out.stdout or "").strip() else {}
    except ValueError:
        ir = {}
    ir.setdefault("dir", src_dir)
    ir.setdefault("functions", [])
    ir.setdefault("call_seen", 0)
    ir.setdefault("call_total", 0)
    return _dedup_keys(ir)


def _dedup_keys(ir):
    """Ensure every function key is unique so no function is overwritten / lost in
    the call graph. The tree-sitter extractor already does this; line-based
    extractors (plsql/vb6/cobol) did not — same-named procedures collapsed to one node."""
    seen = {}
    for f in ir.get("functions") or []:
        k = f.get("key")
        if k in seen:
            seen[k] += 1
            f["key"] = "%s#%d" % (k, seen[k])
        else:
            seen[k] = 0
    return ir


def scan(lang, src_dir, db=DEFAULT_DB, cats=None):
    cats = cats or DEFAULT_CATS
    fam = LANG_FAMILY.get(lang, lang)
    ir = extract_ir(lang, src_dir)
    cg = CallGraph(ir)                       # no SSA for non-Go frontends (yet)
    az = engine.Analyzer(ir, engine.load_spec(db, fam), cg=cg)
    return ir, cg, az.run(cats), fam


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("lang", choices=sorted(LANG_FAMILY))
    ap.add_argument("src")
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--cats", default=",".join(DEFAULT_CATS))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    cats = [c.strip().upper() for c in args.cats.split(",") if c.strip()]
    ir, cg, findings, fam = scan(args.lang, args.src, args.db, cats)
    if args.json:
        print(json.dumps(findings, indent=2, ensure_ascii=False))
        return
    st = cg.stats()
    print(f"\n╔═ Agent A — {args.lang} (family={fam}) ═╗")
    print(f"  target     : {args.src}")
    print(f"  call graph : {st['functions']} funcs, {st['edges']} edges "
          f"{st['resolved_by']}, {st['taint_breaks']} taint-break(s)")
    print(f"  IR calls   : seen={ir.get('call_seen')} total={ir.get('call_total')}")
    print(f"  findings   : {len(findings)}\n")
    for i, f in enumerate(findings, 1):
        print(f"{SEV_ICON.get(f['severity'], '•')} [{i}] {f['category']} "
              f"({f['severity']}, conf={f['confidence']})"
              f"{'  ⟶ inter-procedural' if f['interproc'] else ''}")
        print(f"     sink   : {f['sink']}()  — {f['sink_note']}")
        print(f"     where  : {f['pos']}  (func {f['func']}, line {f['line']})")
        print(f"     source : {f['source']}\n")


if __name__ == "__main__":
    main()
