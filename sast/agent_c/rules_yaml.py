#!/usr/bin/env python3
"""Declarative YAML rule layer (Semgrep-style rules + CodeQL-style config semantics)
that plugs into SAST_k1nz's flow-sensitive + CFG taint engine. Users add
source/sink/sanitizer/propagator definitions without touching code; rules are
merged into the taint spec (so is_source/sinks/sanitizer_of use them unchanged)
and propagators add declarative from→to taint steps (Semgrep propagator /
CodeQL isAdditionalFlowStep).

Rule file (rules/*.yml):

  rules:
    - id: custom-sqli
      family: [php, python]        # optional; omit = all languages
      category: SQLI               # engine category for sinks
      severity: high               # optional
      sources:                     # patterns: bare string = exact callee name
        - "$_GET"
        - regex: "request\\.(args|form|GET)"
      sinks:
        - "custom_query"
        - substr: "_exec"
      sanitizers:
        - "my_escape"
      propagators:                 # declarative taint steps for (library) funcs
        - { call: "my_concat", from: arg, to: return }
        - { call: "builder_add", from: arg, to: receiver }
"""
import os
import re

try:
    import yaml  # PyYAML
except Exception:  # noqa: BLE001
    yaml = None

_CACHE = None   # loaded rule list (parsed once)


def _rules_dir():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # .../sast
    return os.environ.get("SAST_RULES_DIR") or os.path.join(here, "rules")


def _compile(pat):
    """A pattern -> an engine matcher tuple (kind, val) understood by _match()."""
    if isinstance(pat, str):
        return ("call", pat)
    if not isinstance(pat, dict):
        return ("isubstr", str(pat).lower())
    if "regex" in pat:
        try:
            return ("regex", re.compile(pat["regex"]))
        except re.error:
            return ("isubstr", str(pat["regex"]).lower())
    if "substr" in pat:
        return ("isubstr", str(pat["substr"]).lower())
    for k in ("call", "name", "match"):
        if k in pat:
            return ("call", str(pat[k]))
    return ("isubstr", str(pat).lower())


def load():
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    out = []
    d = _rules_dir()
    if yaml is not None and os.path.isdir(d):
        for dp, _dn, fns in os.walk(d):          # recurse into subdirs (e.g. rules/0xdea/)
            for fn in sorted(fns):
                if not fn.lower().endswith((".yml", ".yaml")):
                    continue
                try:
                    doc = yaml.safe_load(open(os.path.join(dp, fn), encoding="utf-8")) or {}
                except Exception:  # noqa: BLE001 — a bad rule file never breaks a scan
                    continue
                rs = doc.get("rules") if isinstance(doc, dict) else None
                for r in (rs or []):
                    if isinstance(r, dict):
                        out.append(r)
    _CACHE = out
    return out


def _fam_ok(rule, family):
    fams = rule.get("family") or rule.get("languages")
    if not fams:
        return True
    if isinstance(fams, str):
        fams = [fams]
    return family in fams


def _entry_m(p):
    """Compile a source/sink/sanitizer entry's matcher. Accepts a bare pattern
    (string / {regex} / {substr}) or a dict with flow-state fields + a matcher key.
    Returns None for a dict with NO matcher key (so it is dropped, not turned into a
    garbage substring matcher) and for a non-string/non-dict scalar."""
    if isinstance(p, dict):
        if any(k in p for k in ("regex", "substr")):
            return _compile(p)
        mk = {k: p[k] for k in ("call", "name", "match", "pattern") if k in p}
        if "pattern" in mk:
            return _compile(mk["pattern"])
        if mk:
            return _compile(next(iter(mk.values())))
        return None                 # matcher-less dict (only flow-state fields) → drop
    if isinstance(p, str):
        return _compile(p)
    return None                     # int/float/other scalar → drop (not a pattern)


def _entry_meta(p):
    """Flow-state metadata on an entry ({state, require_state, to_state}); {} for a bare pattern."""
    return p if isinstance(p, dict) else {}


def _as_list(v):
    """A YAML authoring slip `sinks: "x"` (missing `-`) must NOT be iterated as
    characters (which would make per-character matchers). Treat a scalar as a 1-list."""
    if v is None:
        return []
    if isinstance(v, (str, dict)):
        return [v]
    if isinstance(v, (list, tuple)):
        return list(v)
    return []


def apply(spec, family):
    """Merge YAML rule sources/sinks/sanitizers for `family` into the taint spec
    in place, so the engine's is_source/sinks/sanitizer_of pick them up."""
    for r in load():
        if not _fam_ok(r, family):
            continue
        try:                       # per-rule isolation: one bad rule must not drop the rest
            _apply_one(r, spec, family)
        except Exception:  # noqa: BLE001
            continue
    return spec


def _apply_one(r, spec, family):
    cat = r.get("category", "ANY")
    for p in _as_list(r.get("sources")):
        m = _entry_m(p)
        if m is None:
            continue
        spec["_sources"].append({"m": m, "src_kind": "yaml:" + str(r.get("id", "rule")),
                                 "state": _entry_meta(p).get("state", "taint")})
    node = spec["_categories"].setdefault(cat, {"sinks": [], "sanitizers": []})
    for p in _as_list(r.get("sinks")):
        m = _entry_m(p)
        if m is None:
            continue
        meta = _entry_meta(p)
        rs = meta.get("require_state") or meta.get("require-state")
        if isinstance(rs, str):
            rs = [rs]
        node["sinks"].append({"m": m, "conf": 0.8, "weak": 0,
                              "note": "user rule %s" % r.get("id", ""), "origin": "yaml",
                              "require_state": rs})
    for p in _as_list(r.get("sanitizers")):
        m = _entry_m(p)
        if m is None:
            continue
        meta = _entry_meta(p)
        node["sanitizers"].append({"m": m, "weak": 0, "origin": "yaml",
                                   "to_state": meta.get("to_state") or meta.get("to-state")})
    # Semgrep taint-mode: pattern-sources / pattern-sinks / pattern-sanitizers are AST
    # patterns — reduce call-shaped ones to a callee name and feed the engine (once).
    if r.get("mode") == "taint" or r.get("pattern-sources") or r.get("pattern-sinks"):
        _apply_taint_mode(r, spec, node, family)


def _taint_callees(entry, tslang):
    """All callee names extractable from a pattern-source/sink/sanitizer entry."""
    import semgrep_match as SM
    pats = []
    SM._collect_ops(entry if isinstance(entry, dict) else {"pattern": entry},
                    {"pos": pats, "not": [], "inside": [], "not_inside": [],
                     "focus": [], "mvp": [], "mvr": [], "mvc": []})
    out = []
    for p in pats:
        c = SM.callee_of(p, tslang)
        if c:
            out.append(c)
    return out


_MAX_SCAN_BYTES = 2_000_000   # search-mode skips files larger than this (hang guard)
_FAM_GRAMMAR = {"dotnet": "csharp"}   # taint FAMILY -> a valid tree-sitter grammar


def _apply_taint_mode(r, spec, node, family):
    tslang = _FAM_GRAMMAR.get(family) or _TS_LANG.get(family, family)
    rid = str(r.get("id", "rule"))
    for e in r.get("pattern-sources") or []:
        for name in _taint_callees(e, tslang):
            spec["_sources"].append({"m": ("call", name), "src_kind": "yaml-taint:" + rid})
    for e in r.get("pattern-sinks") or []:
        for name in _taint_callees(e, tslang):
            node["sinks"].append({"m": ("call", name), "conf": 0.85, "weak": 0,
                                  "note": "taint rule %s" % rid, "origin": "yaml"})
    for e in r.get("pattern-sanitizers") or []:
        for name in _taint_callees(e, tslang):
            node["sanitizers"].append({"m": ("call", name), "weak": 0, "origin": "yaml"})


_LANG_ALIAS = {"c": "cpp", "cpp": "cpp", "c++": "cpp", "cplusplus": "cpp",
               "cs": "dotnet", "csharp": "dotnet", "vbnet": "dotnet",
               "js": "javascript", "ts": "javascript", "typescript": "javascript",
               "py": "python"}


def _norm(x):
    x = str(x).strip().lower()
    return _LANG_ALIAS.get(x, x)


# ---- Semgrep search-mode (pattern / patterns / pattern-either / pattern-not) ----
_CALLPAT = re.compile(r"^\s*([A-Za-z_$][\w$.]*)\s*\((.*)\)\s*$", re.S)


# Operators we still cannot evaluate over the coarse IR → the rule is SKIPPED
# (never partial/over-matched → no false positives). `focus-metavariable` is
# cosmetic (which node is highlighted) so it no longer disqualifies a rule.
_UNSUPPORTED = ("metavariable-comparison", "metavariable-regex",
                "pattern-inside", "pattern-not-inside", "pattern-regex",
                "pattern-not-regex")
# characters that indicate an arg expression structure (operators, nested calls,
# indexing) we can't verify — such a pattern is not matched exactly.
_ARG_STRUCT = re.compile(r"[-+*/%<>&|^\[\]]|\w\s*\(")


def _split_top(s):
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur); cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return out


def _parse_callpattern(pat):
    """Compile a Semgrep call pattern into a matcher. Supports: concrete or
    metavariable callee, ellipsis, per-arg string-literal, and ARITY
    (`func($A,$B)` → 2 args). Returns {callee, any_callee, metavar, first_strlit,
    min_arity, ellipsis, complex}. `complex`=True means an arg has structure
    (operators/nested calls) we can't verify → caller should drop it."""
    if not isinstance(pat, str):
        return None
    m = _CALLPAT.match(pat)
    if not m:
        return None
    callee, argstr = m.group(1), m.group(2)
    any_callee = callee.startswith("$")
    toks = _split_top(argstr)
    ellipsis = any(t.strip() == "..." for t in toks)
    concrete = [t for t in toks if t.strip() not in ("", "...")]
    first_strlit = bool(concrete) and bool(re.match(r"""\s*["']""", concrete[0]))
    # arg-structure we CAN now verify via IR flags: multiplication (`$_ * $_`) and
    # address-of (`&$VAR`). Anything else structural → still unverifiable (complex).
    need_mul = any("*" in t for t in concrete)
    need_addr = any(t.strip().startswith("&") for t in concrete)
    rest = [t.strip().lstrip("&").replace("*", " ") for t in concrete]
    complex_ = any(_ARG_STRUCT.search(t) for t in rest)
    return {"callee": None if any_callee else callee, "any_callee": any_callee,
            "metavar": callee if any_callee else None,
            "first_strlit": first_strlit, "min_arity": len(concrete),
            "ellipsis": ellipsis, "complex": complex_,
            "need_mul": need_mul, "need_addr": need_addr}


def _metavar_names(node):
    """From a metavariable-pattern node, return (var, {allowed callee names})
    when it constrains a metavariable to a set of bare identifiers."""
    mvp = node.get("metavariable-pattern")
    if not isinstance(mvp, dict):
        return None, set()
    var = mvp.get("metavariable")
    names = set()

    def grab(n):
        if isinstance(n, str):
            if re.match(r"^[A-Za-z_]\w*$", n.strip()):
                names.add(n.strip())
        elif isinstance(n, dict):
            if isinstance(n.get("pattern"), str):
                grab(n["pattern"])
            for k in ("patterns", "pattern-either"):
                for s in n.get(k) or []:
                    grab(s)
    grab(mvp)
    return var, names


def _gather_mvars(node, mvars):
    """Pre-pass: collect ALL metavariable-pattern name constraints in the rule
    (they can appear after the pattern that uses the metavariable)."""
    if isinstance(node, dict):
        if "metavariable-pattern" in node:
            v, names = _metavar_names(node)
            if v and names:
                mvars[v] = names
        for val in node.values():
            _gather_mvars(val, mvars)
    elif isinstance(node, list):
        for v in node:
            _gather_mvars(v, mvars)


def _collect(node, pos, neg, flags, mvars=None):
    """Gather positive/negative matchers; resolve metavariable callees via
    metavariable-pattern; set flags['bad'] for anything not exactly evaluable."""
    if mvars is None:
        mvars = {}
    if isinstance(node, dict):
        if any(k in node for k in _UNSUPPORTED):
            flags["bad"] = True
        if "metavariable-pattern" in node:
            v, names = _metavar_names(node)
            if not (v and names):
                flags["bad"] = True      # a metavar constraint we can't read → unsafe
        if "pattern" in node:
            _add_pos(node["pattern"], pos, flags, mvars)
        if "pattern-not" in node:
            mt = _parse_callpattern(node["pattern-not"])
            if mt is not None and not mt["complex"] and (not mt["any_callee"] or mt["first_strlit"]):
                neg.append(mt)
        for key in ("patterns", "pattern-either"):
            for sub in node.get(key) or []:
                _collect(sub, pos, neg, flags, mvars)
    elif isinstance(node, str):
        _add_pos(node, pos, flags, mvars)


def _add_pos(pat, pos, flags, mvars):
    mt = _parse_callpattern(pat)
    if mt is None or mt["complex"]:
        flags["bad"] = True              # unparsable or arg-structure we can't verify
        return
    if mt["any_callee"]:
        names = mvars.get(mt["metavar"])
        if not names:
            flags["bad"] = True          # unconstrained $X(...) = over-broad
            return
        for nm in names:                 # expand to concrete callees
            c = dict(mt); c["callee"] = nm; c["any_callee"] = False
            pos.append(c)
    else:
        pos.append(mt)


def _cm(mt, call):
    callee = call.get("callee") or ""
    if not mt.get("any_callee") and mt.get("callee") is not None and callee != mt["callee"]:
        return False
    args = call.get("args") or []
    if mt.get("first_strlit") and not (args and args[0].get("strlit")):
        return False
    n, need = len(args), mt.get("min_arity", 0)
    if mt.get("ellipsis"):
        if n < need:
            return False
    elif need and n != need:
        return False
    if mt.get("need_mul") and not any(a.get("mul") for a in args):
        return False
    if mt.get("need_addr") and not any(a.get("addr") for a in args):
        return False
    return True


def _sev(s):
    s = str(s or "").upper()
    return {"ERROR": "high", "WARNING": "medium", "INFO": "needs-review"}.get(s, "medium")


def _search_rules(lang, fam):
    want = {_norm(lang), _norm(fam)}
    out = []
    for r in load():
        langs = r.get("languages") or r.get("family") or []
        tech = (r.get("metadata", {}) or {}).get("technology") or []
        rlangs = {_norm(x) for x in (list(langs) + list(tech))}
        if rlangs and not (rlangs & want):
            continue
        # only treat as a SEARCH rule when it has no taint operators
        if r.get("sources") or r.get("sinks"):
            continue
        pos, neg, flags, mvars = [], [], {"bad": False}, {}
        _gather_mvars(r, mvars)
        _collect(r, pos, neg, flags, mvars)
        if flags["bad"] or not pos:
            continue
        out.append({"id": r.get("id", "rule"),
                    "category": r.get("category", "AUDIT"),
                    "severity": _sev(r.get("severity")),
                    "message": " ".join(str(r.get("message", "")).split())[:300],
                    "cwe": (r.get("metadata", {}) or {}).get("cwe") or [],
                    "match": pos, "not": neg})
    return out


_TS_LANG = {"vbnet": "vb"}   # ts-pack grammar name differs from the SAST lang id


# source extensions per language — so search rules scan files that produced NO
# extracted function (headers, macro-only / declaration-only files) too.
_LANG_EXTS = {
    "cpp": (".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hpp", ".hh", ".hxx", ".inl", ".ipp"),
    "php": (".php", ".phtml", ".php3", ".php4", ".php5", ".inc"),
    "python": (".py", ".pyi", ".pyw"),
    "java": (".java",), "go": (".go",), "javascript": (".js", ".jsx", ".ts", ".tsx", ".mjs"),
    "ruby": (".rb",), "csharp": (".cs",), "kotlin": (".kt", ".kts"), "rust": (".rs",),
    "swift": (".swift",), "scala": (".scala", ".sc"), "perl": (".pl", ".pm"),
}


def _files_of(ir, lang=None):
    seen = set()
    for f in ir.get("functions") or []:
        pos = f.get("pos", "")
        fp = pos.rsplit(":", 2)[0] if ":" in pos else pos
        if fp:
            seen.add(fp)
    # also include every source file of this language under the target dir, so a
    # file that yielded zero functions (header-only / macro-only) is still scanned.
    root = ir.get("dir")
    exts = _LANG_EXTS.get(lang) or _LANG_EXTS.get(_norm(lang))   # typescript→javascript etc.
    if root and exts and os.path.isdir(root):
        for dp, dns, fns in os.walk(root):
            dns[:] = [d for d in dns if d not in ("vendor", "node_modules", ".git")]
            for fn in fns:
                if fn.endswith(exts):
                    seen.add(os.path.join(dp, fn))
    return sorted(seen)


def _is_searchrule(r, lang, fam):
    if r.get("sources") or r.get("sinks") or r.get("mode") == "taint":
        return False                      # taint rule, not search
    if r.get("pattern-sources") or r.get("pattern-sinks"):
        return False
    if not (r.get("pattern") or r.get("patterns") or r.get("pattern-either")):
        return False
    want = {_norm(lang), _norm(fam)}
    langs = r.get("languages") or r.get("family") or []
    tech = (r.get("metadata", {}) or {}).get("technology") or []
    rl = {_norm(x) for x in (list(langs) + list(tech))}
    return (not rl) or bool(rl & want)


def search_findings(ir, lang, fam):
    """Semgrep-style search findings via the real tree-sitter AST matcher
    (`semgrep_match`): full metavariable/ellipsis/pattern-inside support. Falls
    back to nothing if the matcher/grammar is unavailable (never a wrong match)."""
    try:
        import semgrep_match as SM
    except Exception:  # noqa: BLE001
        return []
    tslang = _TS_LANG.get(lang, lang)
    parser = SM._parser(tslang)
    if parser is None:
        return []
    rules = [r for r in load() if _is_searchrule(r, lang, fam)]
    if not rules:
        return []
    out, seen = [], set()
    for path in _files_of(ir, lang):
        try:
            if os.path.getsize(path) > _MAX_SCAN_BYTES:   # skip huge files (hang guard)
                continue
            src = open(path, "rb").read()
        except OSError:
            continue
        try:
            troot = parser.parse(src).root_node
            nodes = list(SM._walk(troot))   # walk the tree once, reuse for all rules
            SM._CUR_TCTX = SM.build_type_ctx(troot, src)   # types for typed metavars
        except Exception:  # noqa: BLE001
            continue
        base = os.path.basename(path)
        for r in rules:
            try:
                ms = SM.match_rule(r, tslang, troot, src, nodes)
            except Exception:  # noqa: BLE001
                ms = []
            for node, _env in ms:
                line = node.start_point[0] + 1
                key = (r.get("id"), path, line)   # one finding per rule per line
                if key in seen:
                    continue
                seen.add(key)
                snippet = src[node.start_byte:node.end_byte].decode("utf-8", "replace")
                out.append({
                    "category": r.get("category", "AUDIT"), "func": base,
                    "pos": "%s:%d:1" % (path, line), "line": line,
                    "sink": " ".join(snippet.split())[:90],
                    "sink_note": " ".join(str(r.get("message", "")).split())[:300],
                    "source": "pattern-match", "severity": _sev(r.get("severity")),
                    "confidence": 0.75, "rule_id": r.get("id", ""),
                    "cwe": (r.get("metadata", {}) or {}).get("cwe") or [], "search": True,
                })
    return out


def summaries(family):
    """CodeQL Models-as-Data store summaries: [{m, from, to}] where `from`/`to` are
    `receiver` / `arg` / `arg[N]`. Library flow declared as DATA (e.g. strcpy(dst,src):
    from arg[1] to arg[0]) so taint crosses library calls into output parameters."""
    out = []
    for r in load():
        if not _fam_ok(r, family):
            continue
        for p in r.get("summaries") or []:
            if not isinstance(p, dict):
                continue
            m = _compile({k: p[k] for k in ("call", "regex", "substr", "name", "match") if k in p} or p)
            out.append({"m": m, "from": str(p.get("from", "arg")).lower().replace(" ", ""),
                        "to": str(p.get("to", "arg[0]")).lower().replace(" ", "")})
    return out


def propagators(family):
    """[{m, from, to}] — declarative taint steps. from in {arg, receiver},
    to in {return, receiver}."""
    out = []
    for r in load():
        if not _fam_ok(r, family):
            continue
        for p in r.get("propagators") or []:
            if not isinstance(p, dict):
                continue
            m = _compile({k: p[k] for k in ("call", "regex", "substr", "name", "match") if k in p} or p)
            out.append({"m": m, "from": str(p.get("from", "arg")).lower(),
                        "to": str(p.get("to", "return")).lower()})
    return out
