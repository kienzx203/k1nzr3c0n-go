"""
Agent A — taint engine (language-agnostic core, driven by taint_spec.db).

Consumes the IR emitted by a language extractor (currently the Go extractor)
and the taint-spec for that language family, then runs an inter-procedural,
flow-insensitive taint analysis (recall-first, per the "không bỏ sót" goal):

  source  -> (assignments / propagators / cross-function calls+returns) -> sink

- over-approximate: once a variable is tainted it stays tainted (sound for recall)
- inter-procedural: tainted call arguments taint the callee's parameters;
  a function that returns a tainted value is marked taint-returning
- sanitizers: a STRONG sanitizer on the path clears taint; a WEAK one
  (spec weak=1) does NOT clear it but downgrades the finding to needs-review
- SQLI refinement: a tainted value passed as a *placeholder parameter*
  (not concatenated into the query string) is treated as parameterized/safe
- coverage ledger: calls whose callee cannot be resolved are recorded as
  taint-breaks so nothing is silently dropped
"""

import re
import sqlite3

import irutil
from callgraph import CallGraph


def load_spec(db_path, family):
    """Return {category: {'sinks':[...], 'sanitizers':[...]}, '_sources':[...],
    '_propagators':[...]} of compiled matchers for a language family."""
    con = sqlite3.connect(db_path)
    cur = con.cursor()

    def rows(kind, catsel):
        q = ("SELECT DISTINCT pattern,matcher,source_kind,confidence,weak,note,"
             "category,origin FROM signatures WHERE lang_family=? AND kind=?")
        args = [family, kind]
        if catsel == "ANY":
            q += " AND category='ANY'"
        else:
            q += " AND category=?"
            args.append(catsel)
        return cur.execute(q, args).fetchall()

    def compile_sig(pattern, matcher):
        if matcher == "call":
            return ("call", pattern)
        if matcher == "regex":
            try:
                return ("regex", re.compile(pattern))
            except re.error:
                return ("substr", pattern.replace("\\", ""))
        if matcher == "isubstr":
            return ("isubstr", pattern.replace("\\", "").lower())
        return ("substr", pattern.replace("\\", ""))

    spec = {"_sources": [], "_propagators": [], "_categories": {}}
    for pat, matcher, skind, conf, weak, note, cat, origin in rows("source", "ANY"):
        spec["_sources"].append({"m": compile_sig(pat, matcher), "src_kind": skind,
                                 "conf": conf, "note": note, "origin": origin, "pat": pat})
    cats = [r[0] for r in cur.execute(
        "SELECT DISTINCT category FROM signatures WHERE lang_family=? "
        "AND category!='ANY' AND kind IN('sink','sanitizer')", (family,))]
    for cat in cats:
        node = {"sinks": [], "sanitizers": []}
        for pat, matcher, skind, conf, weak, note, c, origin in rows("sink", cat):
            node["sinks"].append({"m": compile_sig(pat, matcher), "conf": conf,
                                  "note": note, "origin": origin, "pat": pat})
        for pat, matcher, skind, conf, weak, note, c, origin in rows("sanitizer", cat):
            node["sanitizers"].append({"m": compile_sig(pat, matcher), "weak": bool(weak),
                                       "conf": conf, "note": note, "pat": pat,
                                       "origin": origin})
        spec["_categories"][cat] = node
    con.close()
    return spec


def _match(sig_m, call):
    """Does a compiled matcher match a call IR node?"""
    kind, val = sig_m
    callee = call.get("callee") or ""
    full = call.get("full") or ""
    if kind == "call":
        return callee == val
    if kind == "regex":
        return bool(val.search(full) or val.search(callee))
    if kind == "isubstr":
        return val in full.lower() or val in callee.lower()
    return val in full or val in callee


# --- deterministic recall layer (language-agnostic) ------------------------- #
# Dangerous "verbs" that commonly denote a sink even when the exact API is NOT in
# taint_spec.db, so a custom/missed sink is still surfaced (recall-first). Used
# only by recall_findings(), which marks hits needs-review for triage.
# ASSIGNMENT sinks: a tainted value written to one of these properties is a sink
# (not a call) — DOM-based XSS and client-side open redirect.
_ASSIGN_SINKS = {
    "XSS": re.compile(r"\.(innerHTML|outerHTML|insertAdjacentHTML)$", re.I),
    "SSRF": re.compile(r"(^|\.)location(\.(href|assign|replace))?$|\.src$", re.I),
    # swift Process / NSTask: tainted command/args written as a property, then launch()
    "CMDI": re.compile(r"\.(arguments|launchPath|executableURL|executable)$", re.I),
    # .NET DirectorySearcher: tainted LDAP filter written as a property, then FindOne()
    "LDAPI": re.compile(r"\.Filter$", re.I),
}

# FORMAT_STRING: the argument index that is the FORMAT string for each known function
# (a format-string bug is that arg being tainted; trailing data args are not the bug).
_FMT_ARG_POS = {
    "printf": 0, "vprintf": 0, "wprintf": 0, "nslog": 0, "format": 0, "scanf": 0,
    "sprintf": 1, "fprintf": 1, "vfprintf": 1, "vsprintf": 1, "sscanf": 1, "fscanf": 1,
    "syslog": 1, "err": 1, "errx": 1, "warn": 1, "warnx": 1, "asprintf": 1, "vasprintf": 1,
    "snprintf": 2, "swprintf": 2, "vsnprintf": 2,
    "stringwithformat": 0, "stringwithformat:": 0, "localizedstringwithformat": 0,
}


def _fmt_arg_pos(callee):
    """Format-argument index for a known format function, else None (fire on any arg)."""
    c = (callee or "").split(".")[-1].split("::")[-1].split("(")[0].strip().lower()
    return _FMT_ARG_POS.get(c)


# A DB/SQL execute method — ARG_INJECTION must not fire here (the DB `exec` regex
# substring-matches `execute`, and a prepared-statement bind is not argument injection).
_SQL_EXEC_CALLEE = re.compile(
    r"(^|[.\\>:])(execute|executeQuery|executeUpdate|executeNonQuery|executeScalar|"
    r"executeReader|exec_query|execute_batch)\b", re.I)

# Heap memory-management functions (HackTricks "Libc Heap"): a pointer passed to one of
# these is freed; a later use or a second free is use-after-free / double-free.
_FREE_FNS = {"free", "kfree", "vfree", "g_free", "delete", "delete[]", "cfree",
             "xfree", "dealloc", "free_sized"}
_REALLOC_FNS = {"realloc", "reallocarray", "g_realloc"}

GENERIC_SINK_RE = re.compile(
    r"(?i)(exec|system|popen|proc_open|passthru|spawn|shell|\bcmd\b|eval|assert|"
    r"compile|create_?function|call_?user_func|query|execute|prepare|raw_?query|"
    r"cursor|include|require|__import__|load|render|template|deserial|unserial|"
    r"unpickle|pickle|marshal|yaml.?load|from_?xml|xmldecode|read_?file|write_?file|"
    r"save_?file|fopen|fwrite|unlink|remove|delete|rmdir|chmod|chown|setattr|"
    r"send|request|fetch|urlopen|redirect|writehead|innerhtml|outerhtml|dangerouslyset)")
# External-input readers that commonly introduce taint (seed extra sources).
# AbsInt-lite: operations that constrain a value to an injection-safe form —
# numeric/type coercions AND one-way hash/hex encoders (output is a fixed
# alnum/hex charset that cannot carry an SQL/command/HTML payload).
_COERCE_RE = re.compile(
    r"(?i)(^|\W)(intval|floatval|doubleval|boolval|parse_?int|parse_?float|"
    r"to_?number|to_?int|number_format|settype|hexdec|octdec|bindec|"
    r"md5|sha1|sha256|sha512|crc32|\bhash\b|hash_hmac|password_hash|bcrypt|"
    r"bin2hex|dechex|getmypid|int|float|bool)\b")
# NOTE: `uniqid` removed — its prefix argument is attacker-controlled (uniqid($p)
# returns $p . hex), so it does NOT sanitize. `int`/`float`/`bool` added for Python's
# bare numeric/boolean coercions. `str` is deliberately NOT here (str() of user input
# is still injectable).

GENERIC_SOURCE_RE = re.compile(
    r"(?i)(getenv|environ|\$env\b|\bstdin\b|\binput\b|scanner|read_?line|getparameter|"
    r"\bparam\b|\bargv\b|query_?string|get_?header|getcookie|\bcookie\b|get_?input|"
    r"request\.(get|post|query|params|body|headers|args|form|files|json)|"
    r"\$_(get|post|request|cookie|server|files|env)|req\.(query|params|body|headers|cookies)|"
    r"stringforkey|valueforkey|objectforkey|userdefaults|queryitems|texting|textfield\.text|"  # objc/swift/ios
    r"request\.(item|form|querystring|params)|\.getquerystring|"                                 # asp/vb.net
    r"\baccept\b|linkage)")                                                                      # cobol ACCEPT / LINKAGE


class Analyzer:
    def __init__(self, ir, spec, cg=None):
        self.spec = spec
        self.funcs = ir.get("functions") or []
        self.cg = cg or CallGraph(ir)      # explicit call graph (full param binding)
        self.by_key = {f["key"]: f for f in self.funcs}
        self.tainted = {f["key"]: set() for f in self.funcs}
        self.origin = {}                   # (fk,var) -> source label
        self.ret_tainted = set()
        # For stored-procedure languages (PL/SQL, COBOL, VB6) a routine PARAMETER is
        # itself the untrusted-input surface (the proc is the entry point, there is no
        # HTTP request object). When set, _find_cat seeds every param as tainted so a
        # param→dynamic-SQL/shell flow surfaces as a TYPED finding, not just RECALL.
        self.params_as_sources = False
        # C-family memory-safety pass (use-after-free / double-free). Set by the
        # orchestrator for C/C++/ObjC.
        self.mem_safety = False
        # closures capture free variables from the enclosing function: map each
        # anonymous func to its parent so taint flows through captured vars.
        self.parent_of = {k: k.rsplit("$func", 1)[0]
                          for k in self.by_key if "$func" in k}
        self._recall = False               # when True, is_source also matches generic input readers
        self.param_to_ret = {}             # func key -> set(param names whose taint reaches the return) — context-sensitive summaries
        self.ret_from_source = set()       # funcs whose return is tainted from an INTERNAL source (context-free)
        self.param_source = False          # treat function params as tainted sources (stored-proc/program entrypoints: plsql/cobol/vb6)
        self.propagators = []              # YAML declarative taint steps [{m,from,to}] (Semgrep propagator / CodeQL additional-flow-step)
        self.summaries = []                # CodeQL Models-as-Data store summaries [{m,from,to}] (arg/receiver -> arg[N]/receiver)
        self.has_states = self._compute_has_states()   # CodeQL flow states active? (gates all state logic)

    # ---- CodeQL Models-as-Data (MaD) store summaries --------------------------
    def _summary_from_tainted(self, fk, call, frm, cat, depth, live):
        """Is the summary's source position (`receiver` / `arg` / `arg[N]`) tainted?"""
        args = call.get("args") or []
        if frm == "receiver":
            r = call.get("recv")
            return self._var_tainted(fk, r, live) if r else (False, None)
        if frm.startswith("arg[") and frm.endswith("]"):
            try:
                i = int(frm[4:-1])
            except ValueError:
                return (False, None)
            if 0 <= i < len(args):
                t, _w, lab = self.expr_tainted(fk, args[i], cat, depth + 1, live)
                return (t, lab)
            return (False, None)
        for a in args:                      # frm == "arg": ANY argument
            t, _w, lab = self.expr_tainted(fk, a, cat, depth + 1, live)
            if t:
                return (True, lab)
        return (False, None)

    def _summary_to_var(self, call, to):
        """Base variable the summary stores taint INTO (`receiver` / `arg[N]`)."""
        if to == "receiver":
            return call.get("recv") or None
        args = call.get("args") or []
        if to.startswith("arg[") and to.endswith("]"):
            try:
                i = int(to[4:-1])
            except ValueError:
                return None
            if 0 <= i < len(args):
                ids = args[i].get("idents") or []
                return ids[0] if ids else None
        return None

    def _store_targets(self, fk, call, cat, live=None, depth=0):
        """Yield (target_var, label) this call taints via a declarative MaD summary
        (arg/receiver -> arg[N]/receiver store step), e.g. strcpy(dst,src): src->dst."""
        out = []
        for s in self.summaries:
            if not _match(s["m"], call):
                continue
            ft, flab = self._summary_from_tainted(fk, call, s["from"], cat, depth, live)
            if not ft:
                continue
            tv = self._summary_to_var(call, s["to"])
            if tv:
                out.append((tv, flab or ("summary %s()" % (call.get("callee") or ""))))
        return out

    # ---- matchers ----
    def _ident_is_source(self, ident):
        """Does an IDENT (a member-path from a subscript/attribute source read, e.g.
        `request.form`, `os.environ`, `sys.argv`, `cookies`) match a source pattern?
        Only idents that look like a framework source path (contain a '.' or are a known
        bare source token) are checked, so an ordinary local variable never matches."""
        if not ident or len(ident) < 3:
            return None
        pseudo = {"callee": ident.rsplit(".", 1)[-1], "full": ident, "recv": ""}
        for s in self.spec["_sources"]:
            if _match(s["m"], pseudo):
                return s
        return None

    def is_source(self, call):
        for s in self.spec["_sources"]:
            if _match(s["m"], call):
                return s
        if self._recall:
            c = (call.get("callee") or "") + " " + (call.get("full") or "")
            if GENERIC_SOURCE_RE.search(c):
                return {"m": None, "src_kind": "generic-input"}
        return None

    def _propagator_return(self, fk, call, cat, depth, live):
        """If a `to:return` propagator matches `call` and its `from` is tainted,
        return a label (the call value is tainted). Declarative arg/receiver→return."""
        for prop in self.propagators:
            if prop.get("to") != "return" or not _match(prop["m"], call):
                continue
            if prop.get("from") == "receiver":
                r = call.get("recv")
                if r and self._var_tainted(fk, r, live)[0]:
                    return "propagator %s(recv→ret)" % (call.get("callee") or "")
            else:  # any argument
                for a in call.get("args") or []:
                    if self.expr_tainted(fk, a, cat, depth + 1, live)[0]:
                        return "propagator %s(arg→ret)" % (call.get("callee") or "")
        return None

    def _is_known_sink(self, call):
        """True if `call` matches any sink signature in any category (already
        covered by the normal pass — not a recall miss)."""
        for cat in self.spec["_categories"]:
            for s in self.spec["_categories"][cat].get("sinks", []):
                if _match(s["m"], call):
                    return True
        return False

    def recall_findings(self, reported=None):
        """Deterministic recall layer ('không bỏ sót'): with taint maximally
        propagated (generic sources on, no sanitizers), report tainted data
        reaching a dangerous-looking call — including a KNOWN sink that the normal
        pass missed because its source was only recognised generically (e.g. a
        per-language input idiom not in the signature DB). `reported` = set of
        (func,line) the signature pass already found, so we don't duplicate."""
        reported = reported or set()
        self._recall = True
        self.tainted = {f["key"]: set() for f in self.funcs}
        self.origin = {}
        self.ret_tainted = set()
        if self.param_source:              # stored-proc/program entrypoints: params are external input
            for f in self.funcs:
                for p in f.get("paramNames") or []:
                    self.tainted[f["key"]].add(p)
                    self.origin[(f["key"], p)] = "entrypoint parameter"
        self._fixpoint("__recall__")       # unknown cat => no sanitizers clear taint
        out, seen = [], set()
        for f in self.funcs:
            fk = f["key"]
            params = set(f.get("paramNames") or [])
            base = {v: self.origin.get((fk, v)) for v in self.tainted.get(fk, ()) if v in params}
            ops = f.get("ops") or []
            seed = self._loop_seed(fk, ops, base, "__recall__") if any(o.get("loop") for o in ops) else {}
            live = dict(base)
            live.update(seed)
            # vars assigned a PURE string literal locally — a later include($x) of such a
            # var is a safe constant path, not dynamic inclusion.
            defined_lit = set()
            for _op in ops:
                if _op.get("op") == "assign":
                    _r = _op.get("rhs") or {}
                    if _r.get("strlit") and not (_r.get("idents") or _r.get("calls")):
                        for _v in _op.get("lhs") or []:
                            defined_lit.add(_v)
            for op in ops:
                for call in self._all_calls(op):
                    full = (call.get("callee") or "") + " " + (call.get("full") or "")
                    # Recall normally flags only generic-dangerous-looking calls. When params
                    # are the untrusted surface (param_source: stored-proc + swift/rust/objc/
                    # vbnet, which rarely expose a request-object source), ALSO flag a tainted
                    # param reaching a KNOWN spec sink — otherwise those per-lang sinks are
                    # invisible to recall even though they are modelled.
                    if not GENERIC_SINK_RE.search(full) and not (self.param_source and self._is_known_sink(call)):
                        continue
                    if (fk, call.get("line")) in reported:
                        continue           # already reported by the signature pass
                    label = None
                    for a in call.get("args") or []:
                        at, aw, al = self.expr_tainted(fk, a, "__recall__", live=live)
                        if at:
                            label = al or "untrusted input"
                            break
                    # known sink invoked on a TAINTED RECEIVER (param_source langs): e.g. swift
                    # `p.arguments=[tainted]; p.launch()` — the taint is on the receiver `p`, not
                    # an argument, so the arg scan above misses it.
                    if label is None and self.param_source and self._is_known_sink(call):
                        recv = call.get("recv")
                        if recv and self._var_tainted(fk, recv, live)[0]:
                            label = "tainted receiver '%s'" % recv
                    # Dynamic file inclusion (LFI/RFI): include/require of a BARE
                    # variable path (no string-literal part) that isn't locally defined —
                    # the value typically comes from request input or an included file
                    # (e.g. DVWA's $file set in a separate source file). Flag needs-review.
                    if label is None and (call.get("callee") in ("include", "require")):
                        args = call.get("args") or []
                        if args:
                            a0 = args[0]
                            ids = a0.get("idents") or []
                            if ids and not a0.get("strlit") and not a0.get("concat") and ids[0] not in defined_lit:
                                label = "dynamic include path (externally-set variable %s)" % ids[0]
                    if label is None:
                        continue
                    line = call.get("line")
                    key = (fk, line, call.get("full"))
                    if key in seen:
                        continue
                    seen.add(key)
                    resolved = bool(self.cg.resolve_callees(fk, call))
                    kind = "heuristic-sink" if resolved else "unresolved-sink"
                    out.append({
                        "category": "RECALL", "func": fk, "pos": f["pos"],
                        "line": line, "sink": call.get("full"),
                        "sink_note": "recall: tainted data reaches a sink the signature DB "
                                     "does not model (%s)" % kind,
                        "source": label, "severity": "needs-review", "confidence": 0.4,
                        "weak_sanitizer": False, "interproc": True, "recall_kind": kind,
                    })
                # flow-sensitive state update (recall respects reassignment kills too)
                if op.get("op") == "assign":
                    t, _w, al = self.expr_tainted(fk, op.get("rhs"), "__recall__", live=live)
                    # property-assignment sink in recall (param_source langs): a tainted value
                    # written to a dangerous property (swift `p.arguments=[tainted]`, DOM
                    # `el.innerHTML=`) is a sink even without a following call-arg flow — the
                    # typed pass needs a real source, so recall covers the param_source case.
                    if t and self.param_source:
                        for v in op.get("lhs") or []:
                            if any(rx.search(v) for rx in _ASSIGN_SINKS.values()):
                                line = op.get("line")
                                key = (fk, line, v, "assign")
                                if key not in seen:
                                    seen.add(key)
                                    out.append({
                                        "category": "RECALL", "func": fk, "pos": f["pos"],
                                        "line": line, "sink": v,
                                        "sink_note": "recall: tainted value assigned to dangerous property %s" % v,
                                        "source": al or "untrusted input (parameter)",
                                        "severity": "needs-review", "confidence": 0.4,
                                        "weak_sanitizer": False, "interproc": True,
                                    })
                                break
                    for v in op.get("lhs") or []:
                        if t:
                            live[v] = al or "tainted"
                        elif not op.get("branch"):  # kill on clean reassign, incl. in loops (back-edge taint re-added by _loop_seed)
                            live.pop(v, None)
                for call in self._all_calls(op):
                    recv = call.get("recv")
                    if recv:
                        for a in call.get("args") or []:
                            at, _a, al = self.expr_tainted(fk, a, "__recall__", live=live)
                            if at:
                                live[recv] = al or "receiver"
                                break
        self._recall = False
        return out

    def sinks(self, cat):
        return self.spec["_categories"].get(cat, {}).get("sinks", [])

    def sanitizer_of(self, call, cat):
        # AbsInt-lite: a numeric/type COERCION (intval/parseInt/Number/…) turns the
        # value into a number, which cannot carry an injection payload — a strong,
        # language-agnostic sanitizer for all injection categories.
        cf = (call.get("callee") or "") + " " + (call.get("full") or "")
        if _COERCE_RE.search(cf):
            return "strong"
        # Only trust curated (kb) / cross-language (generic) sanitizers to CLEAR
        # taint. Mined sanitizers are noisy (e.g. filepath.Join mis-mined as a
        # fix) — trusting them would hide real flows, so they are ignored here.
        for s in self.spec["_categories"].get(cat, {}).get("sanitizers", []):
            if s.get("origin") not in ("kb", "generic", "yaml"):   # trust user YAML sanitizers
                continue
            if s.get("to_state"):          # CodeQL flow-state transition: does NOT clear
                continue                   #   taint, only changes its state (handled below)
            if _match(s["m"], call):
                return "weak" if s["weak"] else "strong"
        return None

    # ---- CodeQL FLOW STATES (state-machine along the flow) --------------------
    def _compute_has_states(self):
        """True iff any rule is state-aware (source state ≠ default, sink require_state,
        or a state-transition sanitizer). When False, all state logic is skipped so
        behaviour is byte-identical to the stateless engine."""
        for s in self.spec.get("_sources", []):
            if s.get("state") and s["state"] != "taint":
                return True
        for cat in self.spec.get("_categories", {}).values():
            for s in cat.get("sinks", []):
                if s.get("require_state"):
                    return True
            for s in cat.get("sanitizers", []):
                if s.get("to_state"):
                    return True
        return False

    def _src_state(self, call):
        s = self.is_source(call)
        return (s.get("state") or "taint") if s else None

    def _state_transition(self, fk, call, cat, live):
        """If a state-transition sanitizer matches `call` and one of its args is
        tainted, return the new state it moves the value into."""
        for s in self.spec["_categories"].get(cat, {}).get("sanitizers", []):
            if not s.get("to_state") or not _match(s["m"], call):
                continue
            for a in call.get("args") or []:
                if self.expr_tainted(fk, a, cat, live=live)[0]:
                    return s["to_state"]
        return None

    def _expr_state(self, fk, expr, cat, live, lstate):
        """State of the taint carried by `expr` (default 'taint'). A wrapping
        state-transition sanitizer takes precedence, then a declared source state,
        then the state of the first tainted variable."""
        if expr is None:
            return "taint"
        for call in expr.get("calls") or []:
            ts = self._state_transition(fk, call, cat, live)
            if ts:
                return ts
            ss = self._src_state(call)
            if ss and ss != "taint":
                return ss
        for vid in expr.get("idents") or []:
            if vid in lstate:
                return lstate[vid]
        return "taint"

    def _var_tainted(self, fk, vid, live=None):
        """Is `vid` tainted? With `live` (a flow-sensitive per-point state) the
        answer is the taint AT THIS program point; without it, the flow-insensitive
        whole-function state (used by the fixpoint / recall)."""
        if live is not None:
            if vid in live:
                return True, live.get(vid) or f"var:{vid}"
            return False, None
        cur, seen = fk, 0
        while cur is not None and seen < 10:
            if vid in self.tainted.get(cur, ()):
                return True, self.origin.get((cur, vid), f"var:{vid}")
            cur = self.parent_of.get(cur)
            seen += 1
        return False, None

    # ---- expression taint ----
    def expr_tainted(self, fk, expr, cat, depth=0, live=None):
        """Return (tainted, weak, label) for an IR expression."""
        if expr is None or depth > 25:
            return (False, False, None)
        label, weak = None, False
        tainted = False
        for vid in expr.get("idents") or []:
            vt, vlab = self._var_tainted(fk, vid, live)
            if vt:
                tainted = True
                label = label or vlab
            else:
                # SUBSCRIPT/ATTRIBUTE source read: `request.form["x"]`, `request.POST[...]`,
                # `sys.argv[1]`, `os.environ[...]`, `cookies[:x]`, `os.Args[1]`,
                # `Request.Cookies[...]` parse as an IDENT (the member path), not a call, so
                # the call-based source matcher misses them. Match the ident against sources.
                sid = self._ident_is_source(vid)
                if sid:
                    tainted = True
                    label = label or f"source {vid} ({sid['src_kind']})"
        for call in expr.get("calls", []) or []:
            # YAML propagator (to:return): declarative arg/receiver -> return taint
            # step for a matched (library) function — authoritative for that call.
            if self.propagators:
                plab = self._propagator_return(fk, call, cat, depth, live)
                if plab:
                    tainted = True
                    label = label or plab
                    continue
            s = self.is_source(call)
            if s:
                tainted = True
                label = label or f"source {call.get('full')} ({s['src_kind']})"
                continue
            callee = call.get("callee")
            # receiver-tainted -> call value tainted (Checkmarx: a method call on a
            # tainted object, e.g. taintedSb.toString(), yields tainted).
            recv = call.get("recv")
            if recv:
                rt, rlab = self._var_tainted(fk, recv, live)
                if rt:
                    tainted = True
                    label = label or rlab or f"receiver {recv}"
                    continue
            callee_keys = self.cg.resolve_callees(fk, call)
            if callee_keys:
                # DEFINED callee: the return taint is decided by the context-sensitive
                # summary, NOT by a blanket arg pass-through (which would re-introduce the
                # context leak, e.g. konst($x){return "c";} should drop taint).
                ctx_ret = False
                for ck in callee_keys:
                    if ck in self.ret_from_source:         # (b) internal source -> context-free
                        ctx_ret = True
                        label = label or f"return of {callee}()"
                        break
                    prs = self.param_to_ret.get(ck)        # (a) context-sensitive param->return
                    if not prs:
                        continue
                    args = call.get("args") or []
                    for b in self.cg._bind(ck, call):
                        if b["param"] in prs and b["arg"] < len(args):
                            at, aw, al = self.expr_tainted(fk, args[b["arg"]], cat, depth + 1, live)
                            if at:
                                ctx_ret = True
                                weak = weak or aw
                                label = label or al or f"return of {callee}()"
                                break
                    if ctx_ret:
                        break
                if ctx_ret:
                    tainted = True
                continue                                    # defined callee: summary is final
            # UNKNOWN/library callee: default pass-through (undefined-method behaviour) —
            # propagate from arguments unless a strong sanitizer wraps them.
            arg_t = False
            arg_label = None
            for a in call.get("args", []) or []:
                at, aw, al = self.expr_tainted(fk, a, cat, depth + 1, live)
                if at:
                    arg_t = True
                    weak = weak or aw
                    arg_label = arg_label or al
            if arg_t:
                san = self.sanitizer_of(call, cat)
                if san == "strong":
                    continue  # cleaned
                if san == "weak":
                    weak = True
                tainted = True
                label = label or arg_label
        return (tainted, weak, label)

    def _all_calls(self, op):
        return irutil.all_calls(op)

    # ---- per-category driver (taint state is reset for each category, because
    #      sanitizers are category-specific; sharing state would leak taint) ----
    def run(self, categories):
        self._build_summaries()            # context-sensitive param->return summaries (once)
        out = []
        for cat in categories:
            self.tainted = {f["key"]: set() for f in self.funcs}
            self.origin = {}
            self.ret_tainted = set()
            self._fixpoint(cat)
            out += self._find_cat(cat)
        if self.mem_safety:
            out += self._find_memsafety()
        out.sort(key=lambda x: (-x["confidence"], x["category"]))
        return out

    def _find_memsafety(self):
        """Intra-procedural USE-AFTER-FREE / DOUBLE-FREE (HackTricks Libc Heap).
        Walk each function's ops in order tracking which pointer vars are currently
        freed; a second free is double-free, any other use (as a call arg or an rhs
        read) is use-after-free. A reassignment clears the freed state."""
        findings, seen = [], set()
        for f in self.funcs:
            fk, freed = f["key"], {}
            for op in f.get("ops") or []:
                line = op.get("line")
                rhs = op.get("rhs") or {}
                lhs = op.get("lhs") or []
                calls = self._all_calls(op)
                freed_this_op = set()
                for call in calls:
                    callee = (call.get("callee") or "").split(".")[-1].rstrip("(")
                    args = call.get("args") or []
                    argv = [v for a in args for v in (a.get("idents") or [])]
                    if callee in _FREE_FNS:
                        for v in argv:
                            if v in freed:
                                key = ("DF", fk, line, v)
                                if key not in seen:
                                    seen.add(key)
                                    findings.append(self._mem_finding(
                                        f, "DOUBLE_FREE", line, v,
                                        "pointer '%s' freed again (first freed at line %s)" % (v, freed[v])))
                            else:
                                freed[v] = line
                                freed_this_op.add(v)
                    else:
                        for v in argv:
                            if v in freed and v not in freed_this_op:
                                key = ("UAF", fk, line, v)
                                if key not in seen:
                                    seen.add(key)
                                    findings.append(self._mem_finding(
                                        f, "USE_AFTER_FREE", line, v,
                                        "freed pointer '%s' used (freed at line %s)" % (v, freed[v])))
                # direct read of a freed var (x = p, return p, *p) — not through a call
                for v in rhs.get("idents") or []:
                    if v in freed and v not in freed_this_op and v not in lhs:
                        key = ("UAF", fk, line, v)
                        if key not in seen:
                            seen.add(key)
                            findings.append(self._mem_finding(
                                f, "USE_AFTER_FREE", line, v,
                                "freed pointer '%s' used (freed at line %s)" % (v, freed[v])))
                # a reassignment allocates fresh memory → clears freed state
                for v in lhs:
                    freed.pop(v, None)
        return findings

    def _mem_finding(self, f, cat, line, var, note):
        return {"category": cat, "func": f["key"], "pos": f["pos"], "line": line,
                "sink": "free(%s)" % var, "sink_note": note,
                "source": "heap pointer '%s'" % var, "severity": "high",
                "confidence": 0.8, "weak_sanitizer": False, "interproc": False}

    # ---- context-sensitive function summaries -----------------------------
    # For each function, which parameters' taint reaches the RETURN value. This
    # lets a call be treated as return-tainting only when THIS call-site passes
    # taint into such a parameter — so a pass-through like wrap($x){return $x;}
    # does NOT leak taint to a caller that passes a clean argument (the main
    # context-insensitivity leak). Intra-procedural + over-approximate (recall).
    def _local_expr_tainted(self, e, local, with_sources=False):
        if not isinstance(e, dict):
            return False
        for v in e.get("idents") or []:
            if v in local:
                return True
        for c in e.get("calls") or []:
            if with_sources and self.is_source(c):
                return True
            if c.get("recv") in local:
                return True
            for a in c.get("args") or []:
                if self._local_expr_tainted(a, local, with_sources):
                    return True
        return False

    def _local_returns_taint(self, f, seed, with_sources):
        """Intra-procedural: does f's return become tainted given `seed` tainted
        vars (+ internal sources if with_sources)? Over-approximate (recall)."""
        local = set(seed)
        ops = f.get("ops") or []
        changed, rounds = True, 0
        while changed and rounds < 30:
            changed, rounds = False, rounds + 1
            for op in ops:
                for c in self._all_calls(op):          # receiver mutation
                    r = c.get("recv")
                    if r and r not in local and any(self._local_expr_tainted(a, local, with_sources)
                                                    for a in c.get("args") or []):
                        local.add(r); changed = True
                if op.get("op") == "assign":
                    if self._local_expr_tainted(op.get("rhs"), local, with_sources):
                        for v in op.get("lhs") or []:
                            if v not in local:
                                local.add(v); changed = True
                elif op.get("op") == "return":
                    for e in op.get("values") or []:
                        if self._local_expr_tainted(e, local, with_sources):
                            return True
        return False

    def _build_summaries(self):
        self.param_to_ret = {}
        self.ret_from_source = set()
        for f in self.funcs:
            rets = set()
            for p in f.get("paramNames") or []:
                if p and self._local_returns_taint(f, {p}, with_sources=False):
                    rets.add(p)
            self.param_to_ret[f["key"]] = rets
            if self._local_returns_taint(f, set(), with_sources=True):
                self.ret_from_source.add(f["key"])

    # ---- fixpoint (single category) ----
    def _fixpoint(self, cat):
        if True:
            changed = True
            rounds = 0
            while changed and rounds < 50:
                changed = False
                rounds += 1
                for f in self.funcs:
                    fk = f["key"]
                    for op in f.get("ops") or []:
                        if op["op"] == "assign":
                            t, w, lab = self.expr_tainted(fk, op.get("rhs"), cat)
                            if t:
                                for v in op.get("lhs", []):
                                    if v not in self.tainted[fk]:
                                        self.tainted[fk].add(v)
                                        self.origin[(fk, v)] = lab or "tainted"
                                        changed = True
                        elif op["op"] == "return":
                            for e in op.get("values", []) or []:
                                t, w, lab = self.expr_tainted(fk, e, cat)
                                if t and fk not in self.ret_tainted:
                                    self.ret_tainted.add(fk)
                                    changed = True
                        # inter-procedural param propagation over the call graph:
                        # bind each tainted argument to the callee parameter(s)
                        # using the graph's full arg→param binding.
                        for call in self._all_calls(op):
                            callee_keys = self.cg.resolve_callees(fk, call)
                            if not callee_keys:
                                continue
                            args = call.get("args") or []
                            for ck in callee_keys:
                                for b in self.cg._bind(ck, call):
                                    a = args[b["arg"]]
                                    at, aw, al = self.expr_tainted(fk, a, cat)
                                    if not at:
                                        continue
                                    pv = b["param"]
                                    if pv not in self.tainted[ck]:
                                        self.tainted[ck].add(pv)
                                        self.origin[(ck, pv)] = al or f"arg from {fk}()"
                                        changed = True
                        # receiver-mutation pass-through (Checkmarx FlowToUndefinedMethod /
                        # IsParamInfluencingOnTargetDefaultBehavior): a tainted argument
                        # passed to recv.method(..) taints recv, so taint follows objects
                        # through builders / collections / wrappers — incl. LIBRARY methods
                        # with no body. This is the key "don't drop flow through unknown
                        # functions" rule.
                        for call in self._all_calls(op):
                            recv = call.get("recv")
                            if not recv or recv in self.tainted[fk]:
                                continue
                            if self.sanitizer_of(call, cat) == "strong":
                                continue
                            for a in call.get("args") or []:
                                at, aw, al = self.expr_tainted(fk, a, cat)
                                if at:
                                    self.tainted[fk].add(recv)
                                    self.origin[(fk, recv)] = al or f"receiver of {call.get('callee')}()"
                                    changed = True
                                    break
                        # CodeQL Models-as-Data store summaries (arg->arg etc.)
                        for call in self._all_calls(op):
                            if self.summaries:
                                for tv, lab in self._store_targets(fk, call, cat):
                                    if tv not in self.tainted[fk]:
                                        self.tainted[fk].add(tv)
                                        self.origin[(fk, tv)] = lab
                                        changed = True

    def _loop_seed(self, fk, ops, base, cat):
        """One ordered update-only pass; returns {var: label} for vars that become
        tainted INSIDE a loop body — fed back as seeds so loop back-edges are sound."""
        pl, seed = dict(base), {}
        for op in ops:
            if op.get("op") == "assign":
                t, _w, lab = self.expr_tainted(fk, op.get("rhs"), cat, live=pl)
                for v in op.get("lhs") or []:
                    if t:
                        pl[v] = lab or "tainted"
                        if op.get("loop"):
                            seed[v] = lab or "tainted"
                    elif not (op.get("loop") or op.get("branch")):
                        pl.pop(v, None)
            for call in self._all_calls(op):
                recv = call.get("recv")
                if recv and self.sanitizer_of(call, cat) != "strong":
                    for a in call.get("args") or []:
                        at, _a, al = self.expr_tainted(fk, a, cat, live=pl)
                        if at:
                            pl[recv] = al or "receiver"
                            if op.get("loop"):
                                seed[recv] = pl[recv]
                            break
                if self.summaries:
                    for tv, lab in self._store_targets(fk, call, cat, live=pl):
                        pl[tv] = lab
                        if op.get("loop"):
                            seed[tv] = lab
        return seed

    # ---- findings (single category) ----
    def _find_cat(self, cat):
        """FLOW-SENSITIVE finding pass: walk each function's ops IN ORDER with a
        per-point taint state `live` (seeded with tainted parameters from the
        inter-procedural fixpoint). A sink fires only if its argument is tainted AT
        THAT point; a clean reassignment KILLS taint, so `x=taint; x=clean; sink(x)`
        no longer reports. Checkmarx-style statement-ordered data flow."""
        findings, seen = [], set()
        for f in self.funcs:
            fk = f["key"]
            params = set(f.get("paramNames") or [])
            base = {v: self.origin.get((fk, v)) for v in self.tainted.get(fk, ()) if v in params}
            if self.params_as_sources:       # stored-proc langs: every param is untrusted input
                for v in params:
                    base.setdefault(v, "stored-procedure parameter (untrusted)")
            for v in (f.get("source_params") or []):   # framework-annotated request params
                base.setdefault(v, "framework request parameter (untrusted)")
            ops = f.get("ops") or []
            # CFG loop pre-pass: compute taint that vars carry ACROSS loop iterations
            # so a sink appearing BEFORE the tainting assign in the same loop (a pure
            # back-edge) is caught. No findings collected here.
            live = dict(base)
            lstate = {v: "taint" for v in live} if self.has_states else None
            # CFG back-edge: at each loop-region ENTRY compute the seed for THAT region
            # only (not a function-global seed) — so taint carried across iterations of
            # loop1 does NOT leak into an unrelated later loop2, while a clean assignment
            # BEFORE a loop still can't kill the loop's own back-edge taint.
            prev_loop = False
            for idx, op in enumerate(ops):
                cur_loop = bool(op.get("loop"))
                if cur_loop and not prev_loop:
                    j = idx
                    while j < len(ops) and ops[j].get("loop"):
                        j += 1
                    region_seed = self._loop_seed(fk, ops[idx:j], dict(live), cat)
                    if region_seed:
                        live.update(region_seed)
                        if self.has_states:
                            for _v in region_seed:
                                lstate.setdefault(_v, "taint")
                prev_loop = cur_loop
                for call in self._all_calls(op):
                    matches = [s for s in self.sinks(cat) if _match(s["m"], call)]
                    if not matches:
                        continue
                    # prefer a curated (kb) match over generic over mined, then
                    # the higher-confidence one — so the real sink sets severity.
                    prio = {"kb": 2, "generic": 1}
                    hit = max(matches, key=lambda s: (prio.get(s["origin"], 0), s["conf"]))
                    args = call.get("args", []) or []
                    fired = False
                    for idx, a in enumerate(args):
                        t, weak, lab = self.expr_tainted(fk, a, cat, live=live)
                        if not t:
                            continue
                        # CodeQL flow states: a sink with require_state fires only for
                        # taint in one of those states (e.g. html-encoded value is "safe"
                        # for an HTML sink). Stateless sinks (no require_state) fire always.
                        if self.has_states and hit.get("require_state"):
                            st = self._expr_state(fk, a, cat, live, lstate)
                            if st not in hit["require_state"]:
                                continue
                        # SQLI: tainted passed as placeholder param (not concatenated) = safe
                        if cat == "SQLI" and idx > 0 and args and \
                           args[0].get("strlit") and not args[0].get("concat"):
                            continue
                        # FORMAT_STRING: only the FORMAT argument tainted is a bug; a tainted
                        # DATA vararg (printf("%s", user)) is not. Fire only at the format
                        # position for known format funcs (position varies: printf=0, sprintf=1,
                        # snprintf=2, syslog=1…). Unknown funcs keep firing on any arg.
                        if cat == "FORMAT_STRING":
                            fp = _fmt_arg_pos(call.get("callee") or call.get("full") or "")
                            if fp is not None and idx != fp:
                                continue
                        # printf-family writes to stdout/a buffer — it is a FORMAT_STRING sink,
                        # never HTML XSS (the DB maps printf→XSS generically for C). Suppress XSS
                        # here so `printf("%s", user)` (constant format, data arg) is not a finding.
                        if cat == "XSS" and _fmt_arg_pos(call.get("callee") or call.get("full") or "") is not None:
                            continue
                        # Prepared-statement bind: `$stmt->execute([$id])` / `cur.execute(sql, params)`
                        # — an execute() whose tainted argument is NOT a concatenated/literal SQL
                        # string is a bound PARAMETER, which is safe. Only a concatenated query
                        # (execute("SELECT "+x)) is injection. Applies across all injection labels
                        # (the DB `exec` regex also substring-matches `execute`). Skips the bind.
                        if _SQL_EXEC_CALLEE.search(call.get("full") or call.get("callee") or "") \
                           and not a.get("concat") and not a.get("strlit"):
                            continue
                        line = call.get("line")
                        key = (cat, fk, line, call.get("full"))
                        if key in seen:
                            break
                        seen.add(key)
                        concat = a.get("concat")
                        if weak:
                            sev, conf = "needs-review", 0.5
                        elif hit["origin"] == "generic":
                            sev, conf = "medium", 0.6
                        elif concat or cat in ("CMDI", "PATH", "SSRF"):
                            sev, conf = "high", min(0.95, hit["conf"] + 0.05)
                        else:
                            sev, conf = "high", hit["conf"]
                        arg_ids = set(a.get("idents") or [])
                        interproc = (bool(arg_ids & set(f.get("paramNames") or [])) or
                                     (lab or "").startswith(("arg from", "return of")) or
                                     bool(a.get("calls")))   # taint arriving via a call = interproc
                        findings.append({
                            "category": cat, "func": fk, "pos": f["pos"],
                            "line": line, "sink": call.get("full"),
                            "sink_note": hit["note"], "source": lab or "untrusted input",
                            "severity": sev, "confidence": round(conf, 2),
                            "weak_sanitizer": weak, "interproc": interproc,
                        })
                        fired = True
                        break
                    # RECEIVER taint: a sink method whose TAINT is in the receiver, not an
                    # argument — e.g. new URL(taint).openConnection(), taintedProc.launch().
                    # Gated to SSRF/CMDI/SSTI only: for SQLI/ARG_INJECTION a prepared-statement
                    # handle ($stmt->execute()) gets marked tainted via bindParam, so a
                    # receiver check there false-positives on the SAFE parameterized pattern.
                    if not fired and cat in ("SSRF", "CMDI", "SSTI", "TEMPLATE_INJECTION"):
                        recv = call.get("recv")
                        rt, rlab = (self._var_tainted(fk, recv, live) if recv else (False, None))
                        if rt:
                            line = call.get("line")
                            key = (cat, fk, line, call.get("full"))
                            if key not in seen:
                                seen.add(key)
                                findings.append({
                                    "category": cat, "func": fk, "pos": f["pos"],
                                    "line": line, "sink": call.get("full"),
                                    "sink_note": hit["note"],
                                    "source": rlab or "tainted receiver",
                                    "severity": "high", "confidence": hit["conf"],
                                    "weak_sanitizer": False,
                                    "interproc": (recv in set(f.get("paramNames") or [])),
                                })
                # --- flow-sensitive state update AT this point (after sink check) ---
                if op.get("op") == "assign":
                    t, _w, lab = self.expr_tainted(fk, op.get("rhs"), cat, live=live)
                    rst = self._expr_state(fk, op.get("rhs"), cat, live, lstate) if (t and self.has_states) else None
                    # ASSIGNMENT SINK (DOM): a tainted value written to a dangerous
                    # property (x.innerHTML / document.location / el.src) is a sink even
                    # though it is not a call — e.g. DOM-based XSS / open redirect.
                    if t and cat in _ASSIGN_SINKS:
                        for v in op.get("lhs") or []:
                            if _ASSIGN_SINKS[cat].search(v):
                                line = op.get("line")
                                key = (cat, fk, line, v)
                                if key not in seen:
                                    seen.add(key)
                                    findings.append({
                                        "category": cat, "func": fk, "pos": f["pos"], "line": line,
                                        "sink": v, "sink_note": "tainted value assigned to %s" % v,
                                        "source": lab or "untrusted input", "severity": "high",
                                        "confidence": 0.85, "weak_sanitizer": False, "interproc": False,
                                    })
                                break
                    for v in op.get("lhs") or []:
                        if t:
                            live[v] = lab or "tainted"
                            if self.has_states:
                                lstate[v] = rst
                        elif not op.get("branch"):  # kill on clean reassign, incl. in loops (back-edge taint re-added by _loop_seed)
                            live.pop(v, None)          # KILL on clean reassignment —
                            if self.has_states:
                                lstate.pop(v, None)
                            #   but NOT inside a loop (a later iteration may re-taint it;
                            #   gen-only in loops keeps it sound against back-edges).
                for call in self._all_calls(op):        # receiver-mutation, in order
                    recv = call.get("recv")
                    if recv and self.sanitizer_of(call, cat) != "strong":
                        for a in call.get("args") or []:
                            at, _a, al = self.expr_tainted(fk, a, cat, live=live)
                            if at:
                                live[recv] = al or ("receiver of %s()" % (call.get("callee") or ""))
                                break
                    if self.summaries:                  # MaD store summaries, in order
                        for tv, lab in self._store_targets(fk, call, cat, live=live):
                            live[tv] = lab
        return findings
