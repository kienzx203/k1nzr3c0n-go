#!/usr/bin/env python3
"""
Agent C — Orchestrator (Tuần 3).

Combines Agent A candidates (Go native SSA/VTA frontend, or any tree-sitter
language frontend), builds an evidence bundle per candidate (source → path →
sink + code), VERIFIES each (pluggable: a deterministic heuristic verifier by
default; an LLM-ready prompt bundle is attached for an optional LLM pass), and
emits a COVERAGE LEDGER of taint-breaks (unresolved/dynamic calls = potential
misses) so nothing is silently dropped.

    python3 agent_c/orchestrator.py <dir> [--lang go|java|...] [--json out.json]

Output (JSON): {target, lang, summary, findings:[{...verdict...,bundle}], ledger}
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "agent_a"))

# the extractor subprocess raises its recursion limit to 13000 and emits IR that deep;
# match it here so the main process can walk that IR (callgraph/irutil/flowpath) without
# an uncaught RecursionError on a deeply-nested call expression.
sys.setrecursionlimit(max(sys.getrecursionlimit(), 13000))

import engine                         # noqa: E402
from callgraph import CallGraph       # noqa: E402
import run_go                         # noqa: E402
import run_lang                       # noqa: E402
import agents as AG                   # noqa: E402 (per-vulnerability agents)

EXT_LANG = {
    ".go": "go", ".py": "python", ".java": "java", ".cs": "csharp",
    ".js": "javascript", ".mjs": "javascript", ".ts": "typescript",
    ".tsx": "typescript", ".php": "php", ".rb": "ruby", ".kt": "kotlin",
    ".swift": "swift", ".rs": "rust", ".c": "cpp", ".cc": "cpp",
    ".cpp": "cpp", ".cxx": "cpp", ".h": "cpp", ".hpp": "cpp",
    ".pl": "perl", ".pm": "perl", ".t": "perl", ".cgi": "perl",
    ".m": "objc", ".mm": "objc", ".vb": "vbnet",
    ".sql": "plsql", ".pks": "plsql", ".pkb": "plsql", ".pls": "plsql",
    ".vbs": "vb6", ".bas": "vb6", ".cls": "vb6", ".frm": "vb6",
    ".cob": "cobol", ".cbl": "cobol", ".cpy": "cobol",
}


def detect_lang(target):
    counts = {}
    for dp, dns, fns in os.walk(target):
        dns[:] = [d for d in dns if d not in ("vendor", "node_modules", ".git")]
        for f in fns:
            ext = os.path.splitext(f)[1]
            if ext in EXT_LANG:
                counts[EXT_LANG[ext]] = counts.get(EXT_LANG[ext], 0) + 1
    return max(counts, key=counts.get) if counts else None


# --------------------------------------------------------------------------- #
# run Agent A
# --------------------------------------------------------------------------- #
def run_agent_a(target, lang, db, cats=None):
    if lang == "go":
        ir = run_go.extract_ir(target)
        cg, mode = run_go.build_graph(target, ir)
    else:
        ir = run_lang.extract_ir(lang, target)
        cg = CallGraph(ir)
        mode = "tree-sitter"
    fam = run_lang.LANG_FAMILY.get(lang, lang)
    cats = cats or run_lang.DEFAULT_CATS
    spec = engine.load_spec(db, fam)
    try:
        import rules_yaml                 # declarative YAML rules (source/sink/sanitizer/propagator)
        rules_yaml.apply(spec, fam)
    except Exception:  # noqa: BLE001 — user rules never break a scan
        rules_yaml = None
    # run any taint categories introduced by YAML rules (Semgrep taint-mode) too,
    # not only the built-in DEFAULT_CATS.
    cats = list(dict.fromkeys(list(cats) + [c for c in spec.get("_categories", {})]))
    az = engine.Analyzer(ir, spec, cg=cg)
    # stored-procedure languages: a routine PARAMETER is the untrusted-input surface,
    # so seed params as sources to get TYPED findings (not just RECALL) for proc(p)→sink.
    # Keyed on LANG, not fam: vb6's family is `dotnet` (shared with csharp/vbnet, which are
    # app languages where params must NOT be auto-sources), so fam would be wrong here.
    az.params_as_sources = lang in ("plsql", "cobol", "vb6")
    az.mem_safety = lang in ("cpp", "objc", "c")   # use-after-free / double-free pass
    if rules_yaml is not None:
        try:
            az.propagators = rules_yaml.propagators(fam)
        except Exception:  # noqa: BLE001
            pass
        try:
            az.summaries = rules_yaml.summaries(fam)   # CodeQL Models-as-Data store steps
        except Exception:  # noqa: BLE001
            pass
    # stored procedures / COBOL programs / VB entry functions receive external
    # input via their parameters — treat params as tainted sources (recall).
    # Also enable param-as-source in the RECALL pass only (NOT params_as_sources, which is
    # the high-confidence typed pass and would flood) for swift/rust/objc/vbnet: these
    # extract cleanly but rarely expose a request-object source in small handlers, so a
    # param reaching a dangerous sink is surfaced as a low-confidence recall candidate
    # (the agent confirms the param is attacker-reachable) — closing the known per-lang FN.
    az.param_source = lang in ("plsql", "cobol", "vb6", "swift", "rust", "objc", "vbnet")
    findings = az.run(cats)
    # deterministic recall layer: tainted data into dangerous calls the signature
    # DB does not model (custom/missed sinks, dynamic callees) — so nothing is
    # silently dropped even without the LLM pass.
    try:
        reported = {(f.get("func"), f.get("line")) for f in findings}
        findings += az.recall_findings(reported)
    except Exception:  # noqa: BLE001 — recall is best-effort, never fail the scan
        pass
    # non-taint access-control pass (BROKEN_ACCESS_CONTROL / IDOR) — the biggest real-world
    # class the taint engine is structurally blind to (the bug is a MISSING guard, not a flow).
    try:
        import access_control               # noqa: E402
        findings += access_control.analyze(target, ir.get("functions") or [])
    except Exception:  # noqa: BLE001 — best-effort, never fail the scan
        pass
    findings = _collapse_categories(findings)
    return ir, cg, findings, mode, fam, az


_SEV_RANK = {"high": 0, "medium": 1, "needs-review": 2, "low": 3}
# preference when ONE sink legitimately matches several categories — keep the most
# specific, fold the rest into `also` (so `eval($x)` is ONE finding, not CMDI+
# CODE_INJECTION+INJECTION; `file_get_contents($x)` is PATH, not PATH+SSRF).
_CAT_PREF = {"SQLI": 0, "CODE_INJECTION": 1, "CMDI": 2, "ARG_INJECTION": 3, "XSS": 3,
             "PATH": 3, "UNRESTRICTED_UPLOAD": 3, "OPEN_REDIRECT": 3, "SSRF": 5,
             "INJECTION": 6, "RECALL": 7}

# Sink-aware category correction: the DB's generic SQLI regex contains `\bexec\b`, so a
# command executor (Runtime.exec / child_process.exec / os.system) ALSO matches SQLI and,
# by _CAT_PREF, wins the collapse → a command injection mislabeled as SQLI. Likewise a
# redirect/Location sink matches both XSS and OPEN_REDIRECT. These regexes detect when a
# category is the DEFINITIVE one for a given sink so collapse can prefer it correctly.
_CMD_SINK_RE = re.compile(
    r"(^|[.\\])(system|exec|execv[ep]?|execl[ep]?|popen|spawn|spawnSync|execSync|fork|"
    r"shell_exec|passthru|proc_open|Shell|ShellExecute|CreateProcess|Runtime|"
    r"ProcessBuilder|Process\.Start|Command|CommandContext)\b", re.I)
_REDIR_SINK_RE = re.compile(r"(redirect|sendRedirect|\blocation\b|Location)", re.I)
_SQL_EXEC_RE = re.compile(r"\b(execute|executeQuery|executeUpdate|query|prepare|cursor|do)\b", re.I)
# C stdio format functions are output/format sinks, NOT HTML XSS — the DB maps printf→XSS
# generically, which is wrong for C. Prefer FORMAT_STRING and demote XSS for these.
_FMT_SINK_RE = re.compile(r"(^|[.\\>:])(v?[fs]?printf|v?snprintf|syslog|NSLog|stringWithFormat)", re.I)


def _cat_pref(f):
    """Sink-aware preference used by the collapse: returns a value LOWER than the DB's
    spurious category when the sink text makes the correct category unambiguous."""
    cat = f.get("category"); sink = f.get("sink") or ""
    if cat == "CMDI" and _CMD_SINK_RE.search(sink):
        return -2                              # a real command executor beats spurious SQLI
    if cat == "OPEN_REDIRECT" and _REDIR_SINK_RE.search(sink):
        return -2                              # a real redirect beats XSS/SSRF on the same sink
    if cat == "SQLI" and _CMD_SINK_RE.search(sink) and not _SQL_EXEC_RE.search(sink):
        return 8                               # bare `exec` matched by the SQLI regex → demote
    if cat == "FORMAT_STRING" and _FMT_SINK_RE.search(sink):
        return -1                              # a real format function is FORMAT_STRING, not XSS
    if cat == "XSS" and _FMT_SINK_RE.search(sink):
        return 8                               # printf-family is not HTML XSS → demote
    return _CAT_PREF.get(cat, 4)


def _collapse_categories(findings):
    """Collapse taint findings that are the SAME vulnerability (same function, line and
    sink) but matched under several overlapping categories into one, keeping the most
    specific category and listing the others in `also`."""
    best = {}
    for f in findings:
        k = (f.get("func"), f.get("line"), f.get("sink"))
        pref = _cat_pref(f)
        # a DEFINITIVE sink-based category (pref < 0) also wins over a higher-severity but
        # wrong label, so a command executor is CMDI even if a spurious SQLI hit is "high".
        definitive = 0 if pref < 0 else 1
        rank = (definitive, _SEV_RANK.get(f.get("severity"), 9),
                -(f.get("confidence") or 0), pref)
        cur = best.get(k)
        if cur is None or rank < cur[0]:
            if cur is not None:
                f.setdefault("also", []).append(cur[1].get("category"))
                f["also"].extend(cur[1].get("also") or [])
            best[k] = (rank, f)
        else:
            cur[1].setdefault("also", []).append(f.get("category"))
    out = []
    for _rank, f in best.values():
        if f.get("also"):
            f["also"] = sorted({c for c in f["also"] if c and c != f.get("category")})
        out.append(f)
    return out


# --------------------------------------------------------------------------- #
# evidence bundle: inter-procedural caller chain + code snippet
# --------------------------------------------------------------------------- #
def caller_chain(cg, func_key, max_depth=8):
    """Shortest path from an entry (no callers) down to func_key, via the graph."""
    node = cg.nodes.get(func_key)
    if not node:
        return [func_key]
    # BFS backward over callers
    from collections import deque
    prev = {func_key: None}
    q = deque([func_key])
    entry = func_key
    while q:
        k = q.popleft()
        callers = cg.nodes.get(k, {}).get("callers") or []
        if not callers:
            entry = k
            break
        for c in callers:
            if c not in prev and len(prev) < 200:
                prev[c] = k
                q.append(c)
    chain, k = [], entry
    seen = set()
    while k is not None and k not in seen and len(chain) < max_depth:
        seen.add(k)
        chain.append(k)
        k = prev.get(k)
    return chain  # entry → ... → sink func


def _file_of(pos):
    return pos.rsplit(":", 2)[0] if pos and ":" in pos else None


_FILE_LINES = {}   # path -> splitlines() cache (read each file ONCE, not per graph node)


def _file_lines(path):
    if path not in _FILE_LINES:
        try:
            _FILE_LINES[path] = open(path, encoding="utf-8", errors="replace").read().splitlines()
        except OSError:
            _FILE_LINES[path] = []
    return _FILE_LINES[path]


def snippet_at(path, line, radius=3):
    """Code window centred on a given 1-based line of a file."""
    if not path or not line:
        return ""
    lines = _file_lines(path)
    lo, hi = max(0, line - 1 - radius), min(len(lines), line + radius)
    return "\n".join(f"{i+1:>4}| {lines[i]}" for i in range(lo, hi))


def snippet_for(f, radius=3):
    """Window around the SINK line (f['line']) in the finding's file."""
    return snippet_at(_file_of(f.get("pos", "")), f.get("line"), radius)


def build_bundle(f, cg):
    chain = caller_chain(cg, f["func"])
    # per-hop code: the code at each function on the path (entry → ... → sink),
    # so the verifier sees the WHOLE inter-procedural flow, not just the sink line.
    hops = []
    for key in chain:
        node = cg.nodes.get(key) or {}
        pos = node.get("pos", "")
        hops.append({"func": key,
                     "code": snippet_at(_file_of(pos),
                                        int(pos.rsplit(":", 2)[1]) if pos.count(":") >= 2 else None,
                                        radius=4)})
    return {
        "path": chain,
        "hops": hops,
        "interproc": f.get("interproc", False),
        "code": snippet_for(f),
        "llm_prompt": llm_prompt(f, chain),
    }


def llm_prompt(f, chain):
    return (
        "You are a security reviewer. Decide if this taint flow is a REAL, "
        "exploitable vulnerability or a false positive.\n"
        f"Category: {f['category']}\n"
        f"Source: {f['source']}\n"
        f"Sink: {f['sink']}()  ({f['sink_note']})\n"
        f"Call path (entry→sink): {' -> '.join(chain)}\n"
        f"Code around sink:\n{f.get('_code','')}\n"
        "Answer strictly as JSON: "
        '{\"verdict\":\"confirmed|likely|false_positive\",\"reason\":\"...\"}'
    )


# --------------------------------------------------------------------------- #
# verifiers (pluggable)
# --------------------------------------------------------------------------- #
def heuristic_verify(f):
    """Deterministic triage of a candidate (no LLM). Returns (verdict, score, reason)."""
    cat = f["category"]
    conf = f.get("confidence", 0.5)
    weak = f.get("weak_sanitizer", False)
    interproc = f.get("interproc", False)
    sink = (f.get("sink") or "").lower()

    if weak:
        return "needs-review", 0.5, "only a weak sanitizer on the path"
    # name-only over-match risk: generic low-confidence sink on a non-library-looking recv
    if conf <= 0.45:
        return "needs-review", 0.45, "generic/low-confidence sink match — confirm the sink is the real API"
    # strong signals
    if conf >= 0.9 and not weak:
        return ("confirmed", 0.9,
                "high-confidence curated sink with tainted data" +
                (" across functions" if interproc else ""))
    if 0.6 <= conf < 0.9:
        return ("likely", conf,
                "sink matched with tainted data" +
                (" (inter-procedural)" if interproc else ""))
    return "likely", conf, "tainted data reaches sink"


# --------------------------------------------------------------------------- #
def orchestrate(target, lang=None, db=None, verifier=heuristic_verify,
                llm_model=None, agents_on=None):
    db = db or os.path.join(ROOT, "taint_spec.db")
    _FILE_LINES.clear()                 # per-scan snippet cache (bound memory, no stale reads)
    lang = lang or detect_lang(target)
    if not lang:
        raise SystemExit("could not detect a supported language in the target")
    cats = AG.cats_for(agents_on) if agents_on else None
    ir, cg, findings, mode, fam, az = run_agent_a(target, lang, db, cats=cats)

    # template-engine unescaped-output / SSTI scan — template files are not parsed by the
    # per-language extractor, so XSS in Blade/Jinja/ERB/Vue/Handlebars would be invisible.
    try:
        import templates as _tpl
        findings += _tpl.scan(target)
    except Exception:  # noqa: BLE001 — best-effort, never fail the scan
        pass

    # non-taint structural weaknesses (hardcoded secrets / weak crypto / mass-assignment /
    # CSRF-disabled) — pattern/absence bugs with no source→sink flow.
    try:
        import weakness_scan as _ws
        findings += _ws.scan(target)
    except Exception:  # noqa: BLE001 — best-effort, never fail the scan
        pass

    # dedupe candidates by (category, func, line, sink)
    seen, cands = set(), []
    for f in findings:
        k = (f["category"], f["func"], f["line"], f["sink"])
        if k in seen:
            continue
        seen.add(k)
        cands.append(f)

    # optional LLM verify (via Claude subscription, headless `claude -p`)
    llm_verdicts = {}
    if llm_model:
        import llm_verify
        items = []
        for i, f in enumerate(cands):
            b = build_bundle(f, cg)
            ag = AG.agent_for(f["category"])
            items.append({"index": i, "category": f["category"],
                          "source": f.get("source"), "sink": f.get("sink"),
                          "sink_note": f.get("sink_note"), "path": b["path"],
                          "agent": ag["name"],
                          "focus": AG.skill_focus(ag["id"], ag["hint"]),
                          "code": snippet_for(f, radius=4)})
        llm_verdicts = llm_verify.verify_findings(items, model=llm_model)

    verified = []
    for i, f in enumerate(cands):
        f["_code"] = snippet_for(f)
        bundle = build_bundle(f, cg)
        verdict, score, reason = verifier(f)
        by = "heuristic"
        if i in llm_verdicts:                       # LLM decision wins when present
            lv = llm_verdicts[i]
            verdict = lv["verdict"] or verdict
            reason = lv["reason"] or reason
            by = "llm"
        ag = AG.agent_for(f["category"])
        verified.append({
            **{k: v for k, v in f.items() if not k.startswith("_")},
            "agent": ag["id"], "agent_name": ag["name"],
            "verdict": verdict, "verify_score": round(score, 2),
            "verify_reason": reason, "verified_by": by, "bundle": bundle,
        })
    order = {"confirmed": 0, "likely": 1, "needs-review": 2, "false_positive": 3}
    verified.sort(key=lambda x: (order.get(x["verdict"], 9), -x["verify_score"]))

    # #2 — attach the statement-level def→use flow (source→…→sink) to each finding.
    # Build the whole-program call-site index ONCE (was rebuilt per finding → O(n²)).
    import flowpath
    try:
        _fp_sites = flowpath._callsites(ir, cg)
        _fp_bykey = {f["key"]: f for f in ir.get("functions") or []}
    except Exception:  # noqa: BLE001
        _fp_sites, _fp_bykey = {}, {}
    for v in verified:
        try:
            v["flow"] = flowpath.build(az, ir, cg, v, sites=_fp_sites, by_key=_fp_bykey)
        except Exception:  # noqa: BLE001 — path is best-effort, never fail the scan
            v["flow"] = []

    # Semgrep-style SEARCH-mode rules (pattern match of dangerous constructs — no
    # taint flow needed). Appended as findings with the rule's severity.
    try:
        import rules_yaml
        for sf in rules_yaml.search_findings(ir, lang, fam):
            ag = AG.agent_for(sf["category"])
            verified.append({**sf, "agent": ag["id"], "agent_name": ag["name"],
                             "verdict": "likely" if sf["severity"] == "high" else "needs-review",
                             "verify_score": sf.get("confidence", 0.7),
                             "verify_reason": "rule %s" % sf.get("rule_id", ""),
                             "verified_by": "yaml-rule", "flow": []})
    except Exception:  # noqa: BLE001
        pass

    # coverage ledger — potential misses (taint-breaks)
    st = cg.stats()
    breaks = [u for u in cg.unresolved
              if u["reason"] in ("unknown-func", "dynamic/interface")]
    ledger = {
        "taint_breaks": breaks,
        "external_calls": st.get("unresolved", 0),
        "note": "taint-breaks are unresolved user/dynamic calls that could hide a "
                "flow — review manually; external library calls are handled by the spec.",
    }

    by_verdict = {}
    for v in verified:
        by_verdict[v["verdict"]] = by_verdict.get(v["verdict"], 0) + 1
    summary = {
        "language": lang, "family": fam, "engine": mode,
        "functions": st["functions"], "edges": st["edges"],
        "candidates": len(cands), "by_verdict": by_verdict,
        "taint_breaks": len(breaks),
        "agents": AG.roster(verified),       # per-vulnerability agent roster
    }

    # call graph for the UI graph view (nodes = functions, edges = calls)
    sink_funcs = {f["func"] for f in verified}
    func_sinks = {}  # func key -> [sink line, ...] (for highlighting real source)
    for f in verified:
        func_sinks.setdefault(f["func"], []).append(f.get("line"))

    def _line_of(pos):
        q = (pos or "").rsplit(":", 2)
        return int(q[1]) if len(q) == 3 and q[1].isdigit() else None

    def _relpath(p):
        i = (p or "").find("/src/")
        return p[i + 5:] if i >= 0 else os.path.basename(p or "")

    # per-file sorted function-decl lines → approximate each function's extent
    # (decl line → line before the next function in the same file).
    file_starts = {}
    for _n in cg.nodes.values():
        _absf = _file_of(_n.get("pos", "")); _ll = _line_of(_n.get("pos", ""))
        if _absf and _ll:
            file_starts.setdefault(_absf, []).append(_ll)
    for _absf in file_starts:
        file_starts[_absf] = sorted(set(file_starts[_absf]))

    def _endline(absf, ln):
        nxt = [s for s in (file_starts.get(absf) or []) if s > ln]
        return (min(nxt) - 1) if nxt else None

    # full real source of every referenced file (so the UI shows actual code in
    # context, not just a window), capped so localStorage on the client is safe.
    gfiles, _tot = {}, 0
    for _absf in sorted(file_starts):
        try:
            _txt = open(_absf, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        if len(_txt) > 240000:
            _txt = _txt[:240000] + "\n… (truncated)"
        if _tot + len(_txt) > 3_000_000:
            break
        gfiles[_relpath(_absf)] = _txt
        _tot += len(_txt)

    # Emit EVERY function as a graph node — no function is dropped from the graph.
    # To bound payload size, the per-node source snippet is only inlined for the
    # most relevant nodes (findings/entrypoints + a budget); every other node
    # still carries file/line/end and reads its source from `graph.files`.
    # endpoint→function REACHABILITY: map each extracted entry point to its handler
    # function, then BFS the call graph to the set of functions reachable from an entry.
    # Functions NOT reachable from any entry are dead code or un-wired (the agent should
    # investigate why they exist, or deprioritise them) — this turns the function
    # denominator from "every function" into "every function, labelled by real reachability".
    entry_keys, reachable = set(), set()
    try:
        import entrypoints as _ep
        import os.path as _osp
        bybase = {}
        for _k, _n in cg.nodes.items():
            _f = _file_of(_n.get("pos", ""))
            _l = _line_of(_n.get("pos", ""))
            if _f and _l:
                bybase.setdefault(_osp.basename(_f), []).append((_l, _k))
        for _v in bybase.values():
            _v.sort()
        for _e in _ep.extract(target):
            _cands = bybase.get(_osp.basename(_e.get("file", "")), [])
            _pick = None
            for _l, _k in _cands:                 # handler def sits at/after the route line
                if _l >= _e.get("line", 0):
                    _pick = _k
                    break
            if _pick is None and _cands:
                _pick = _cands[-1][1]
            if _pick:
                entry_keys.add(_pick)
        reachable = set(entry_keys)
        _stack = list(entry_keys)
        while _stack:
            for _cal in cg.nodes.get(_stack.pop(), {}).get("callees", ()):
                if _cal not in reachable:
                    reachable.add(_cal)
                    _stack.append(_cal)
    except Exception:  # noqa: BLE001 — reachability is advisory, never fail the scan
        entry_keys, reachable = set(), set()

    CODE_BUDGET = 3000
    gnodes, gedges = [], []
    _unreached = []
    for _i, (k, n) in enumerate(cg.nodes.items()):
        params = n.get("params") or []
        _pos = n.get("pos", "")
        _absf = _file_of(_pos)
        _line = _line_of(_pos)
        _is_find = k in sink_funcs
        _want_code = _is_find or not n.get("callers") or _i < CODE_BUDGET
        _reach = (not entry_keys) or (k in reachable)  # no entries found → don't claim anything
        if entry_keys and not _reach and not n.get("name", "").startswith("<"):
            _unreached.append(k)
        gnodes.append({"id": k, "label": n.get("name", k) + "(" + ", ".join(params) + ")",
                       "finding": _is_find,
                       "root": not (n.get("callers")),
                       "entry": k in entry_keys,
                       "reachable": _reach,
                       "pos": _pos, "file": _relpath(_absf) if _absf else "",
                       "line": _line,
                       "end": _endline(_absf, _line) if (_absf and _line) else None,
                       "sinks": sorted({x for x in func_sinks.get(k, []) if x}),
                       "code": (snippet_at(_absf, _line, 8)[:1400] if _want_code else "")})
    keyset = {g["id"] for g in gnodes}
    for e in cg.edges:
        if e["caller"] in keyset and e["callee"] in keyset:
            gedges.append({"source": e["caller"], "target": e["callee"],
                           "res": e["resolution"],
                           "label": ",".join(b["param"] for b in e.get("bindings", []))})
    graph = {"nodes": gnodes, "edges": gedges, "files": gfiles,
             "truncated": False, "total_nodes": len(cg.nodes),
             "entries": len(entry_keys), "reachable": len(reachable),
             "unreached": _unreached[:50]}
    return {"target": target, "summary": summary, "findings": verified,
            "ledger": ledger, "graph": graph}


MARKERS = ("go.mod", "package.json", "pom.xml", "build.gradle", "build.gradle.kts",
           "Cargo.toml", "composer.json", "pyproject.toml", "requirements.txt",
           "setup.py", "Gemfile", "build.sbt", "Package.swift", "CMakeLists.txt")
SKIP_DIRS = {"vendor", "node_modules", ".git", "__pycache__", "dist", "build",
             "target", ".idea", ".vscode"}


def _has_source(d):
    for dp, dns, fns in os.walk(d):
        dns[:] = [x for x in dns if x not in SKIP_DIRS]
        if any(os.path.splitext(f)[1] in EXT_LANG for f in fns):
            return True
    return False


def _is_marker(f):
    return f in MARKERS or f.endswith((".csproj", ".sln"))


def discover_targets(root):
    """Split an upload into independent project targets so unrelated sources are
    analysed in ISOLATION (each gets its own call graph + taint run).

    Rule: if the upload ROOT is itself a project (a build marker like go.mod /
    package.json / pom.xml / Cargo.toml / composer.json / requirements.txt ...
    sits directly at the root), the whole upload is ONE target. Otherwise the
    upload is treated as a CONTAINER of several sources: every top-level
    sub-directory that contains source becomes its own target, plus any loose
    source files at the root. This handles both a single uploaded project and a
    zip holding many sibling projects (with or without build files)."""
    rootabs = os.path.abspath(root)
    try:
        entries = sorted(os.listdir(root))
    except OSError:
        return [("/", rootabs)]
    files = [e for e in entries if os.path.isfile(os.path.join(root, e))]
    if any(_is_marker(f) for f in files):
        return [("/", rootabs)]                       # single project at root

    # If the ROOT itself holds source files (e.g. DVWA's index.php / login.php at
    # top level), the root IS the application — its code references the sub-folders,
    # so the whole tree is ONE target. Splitting it into per-folder targets would
    # (a) duplicate findings (root scans everything recursively AND each sub-dir is
    # scanned again) and (b) BREAK any taint/call path that crosses folders, since a
    # callee's file would live in a different target. Only a pure CONTAINER (no code
    # at the root, just sibling project directories) is split into separate targets.
    if any(os.path.splitext(f)[1] in EXT_LANG for f in files):
        return [("/", rootabs)]                       # root has app code → one project

    targets = []
    for d in entries:
        p = os.path.join(root, d)
        if os.path.isdir(p) and d not in SKIP_DIRS and _has_source(p):
            targets.append((d, os.path.abspath(p)))   # each sibling source
    return targets or [("/", rootabs)]


def _empty_graph():
    # same shape as a successful target's graph so a UI consumer never trips on
    # missing keys for an error/empty target.
    return {"nodes": [], "edges": [], "files": {}, "total_nodes": 0, "truncated": False}


def orchestrate_multi(root, lang=None, db=None, llm_model=None, max_targets=200,
                      agents_on=None):
    targets = discover_targets(root)[:max_targets]
    results = []
    for name, path in targets:
        try:
            r = orchestrate(path, lang, db, llm_model=llm_model, agents_on=agents_on)
        except SystemExit as e:
            r = {"summary": {}, "findings": [], "ledger": {"taint_breaks": []},
                 "graph": _empty_graph(), "error": str(e)}
        except Exception as e:  # noqa
            r = {"summary": {}, "findings": [], "ledger": {"taint_breaks": []},
                 "graph": _empty_graph(), "error": "scan failed: %s" % e}
        r["name"] = name
        r["target"] = path
        results.append(r)
    return {"count": len(results),
            "targets": sorted(results, key=lambda x: -len(x.get("findings", [])))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--lang")
    ap.add_argument("--db", default=os.path.join(ROOT, "taint_spec.db"))
    ap.add_argument("--json")
    ap.add_argument("--llm", nargs="?", const="haiku", default=None,
                    metavar="MODEL", help="LLM-verify via Claude subscription "
                    "(claude -p); optional model alias (default haiku)")
    ap.add_argument("--multi", action="store_true",
                    help="split the upload into independent project targets")
    ap.add_argument("--agent", help="only run these vulnerability agents "
                    "(comma list of ids, e.g. sqli,xss,cmdi)")
    args = ap.parse_args()
    ags = [a.strip() for a in args.agent.split(",")] if args.agent else None
    if args.multi:
        result = orchestrate_multi(args.target, args.lang, args.db,
                                   llm_model=args.llm, agents_on=ags)
    else:
        result = orchestrate(args.target, args.lang, args.db,
                             llm_model=args.llm, agents_on=ags)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, ensure_ascii=False)
        print(f"wrote {args.json}")
    if "targets" in result:
        print(f"\n╔═ Agent C — {result['count']} target(s) ═╗")
        for t in result["targets"]:
            s = t.get("summary", {})
            print(f"  ● {t['name']:<24} {s.get('language','?'):<8} "
                  f"{len(t.get('findings', []))} findings"
                  + (f"  [{t['error']}]" if t.get('error') else ""))
        return
    s = result["summary"]
    print(f"\n╔═ Agent C — Orchestrator ═╗")
    print(f"  target   : {result['target']}")
    print(f"  lang     : {s['language']} (engine {s['engine']})")
    print(f"  graph    : {s['functions']} funcs, {s['edges']} edges")
    print(f"  candidates: {s['candidates']}  verdicts: {s['by_verdict']}")
    print(f"  taint-breaks (potential misses): {s['taint_breaks']}\n")
    for i, f in enumerate(result["findings"], 1):
        print(f"  [{i}] {f['verdict'].upper():<12} {f['category']:<6} "
              f"{f['sink']}()  (score {f['verify_score']})")
        print(f"      path  : {' → '.join(f['bundle']['path'])}")
        print(f"      source: {f['source']}   reason: {f['verify_reason']}")


if __name__ == "__main__":
    main()
