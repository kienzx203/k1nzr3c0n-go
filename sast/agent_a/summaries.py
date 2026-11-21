"""
Agent A — function summaries (model "C", Snyk/Semgrep-style, for scale).

Instead of re-walking callee bodies at every call, each function is summarized
ONCE into a compact fact set, then callers reason over callee summaries. This is
how interprocedural SAST scales to large repos.

Per (function, category) summary:
  param_to_return : param names whose taint flows to the function's return
  src_to_return   : an internal source flows to the return (taint-returning)
  param_to_sink   : param names that reach a sink inside (caller-tainted = bug)
  self_findings   : a source reaches a sink WITHIN the function (self-contained)

Taint is tracked symbolically with tokens:
  "SRC"      — value derives from an untrusted source
  "p:<name>" — value derives from parameter <name>

Summaries are computed to a global monotone fixpoint (handles recursion), using
the engine's source/sink/sanitizer matchers and the call graph's arg→param
binding. Findings = SRC reaching a sink (within a function, or across a call).
"""

import irutil


class SummaryEngine:
    def __init__(self, analyzer, categories):
        self.az = analyzer          # engine.Analyzer (reuse matchers + call graph)
        self.cg = analyzer.cg
        self.cats = categories
        self.summaries = {}         # (fk, cat) -> summary dict
        self.var_env = {}           # (fk, cat) -> final var_tokens (for closures)
        self.parent_of = {f["key"]: f["key"].rsplit("$func", 1)[0]
                          for f in analyzer.funcs if "$func" in f["key"]}
        self.findings = []

    # ---- token flow over an expression ----
    def _tokens(self, fk, expr, cat, var_tokens, depth=0):
        if not expr or depth > 25:
            return set()
        toks = set()
        for vid in expr.get("idents") or []:
            toks |= var_tokens.get(vid, set())
        for call in expr.get("calls") or []:
            if self.az.is_source(call):
                toks.add("SRC")
                continue
            san = self.az.sanitizer_of(call, cat)
            if san == "strong":
                continue  # cleaned
            ck = self.cg.resolve_callees(fk, call)
            if ck:
                for k in ck:
                    s = self.summaries.get((k, cat))
                    if not s:
                        continue
                    if s["src_to_return"]:
                        toks.add("SRC")
                    for b in self.cg._bind(k, call):
                        if b["param"] in s["param_to_return"]:
                            toks |= self._tokens(fk, call["args"][b["arg"]], cat,
                                                 var_tokens, depth + 1)
            else:
                for a in call.get("args") or []:
                    toks |= self._tokens(fk, a, cat, var_tokens, depth + 1)
        return toks

    # ---- one function's summary for one category ----
    def _summarize(self, func, cat):
        fk = func["key"]
        params = func.get("paramNames") or []
        var_tokens = {p: {"p:" + p} for p in params}
        # closures inherit captured free variables from the enclosing function
        parent = self.parent_of.get(fk)
        if parent:
            for v, toks in self.var_env.get((parent, cat), {}).items():
                var_tokens[v] = var_tokens.get(v, set()) | toks
        # within-function fixpoint over assignments (flow-insensitive)
        changed = True
        while changed:
            changed = False
            for op in func.get("ops") or []:
                if op.get("op") != "assign":
                    continue
                t = self._tokens(fk, op.get("rhs"), cat, var_tokens)
                for v in op.get("lhs") or []:
                    cur = var_tokens.get(v, set())
                    if not t <= cur:
                        var_tokens[v] = cur | t
                        changed = True

        self.var_env[(fk, cat)] = var_tokens
        summ = {"param_to_return": set(), "src_to_return": False,
                "param_to_sink": set(), "self_findings": []}
        local_find = []
        for op in func.get("ops") or []:
            if op.get("op") == "return":
                for v in op.get("values") or []:
                    t = self._tokens(fk, v, cat, var_tokens)
                    if "SRC" in t:
                        summ["src_to_return"] = True
                    for tok in t:
                        if tok.startswith("p:"):
                            summ["param_to_return"].add(tok[2:])
            for call in irutil.all_calls(op):
                args = call.get("args") or []
                # (1) direct sink in this function
                hit = self._best_sink(call, cat)
                if hit:
                    for a in args:
                        at = self._tokens(fk, a, cat, var_tokens)
                        if cat == "SQLI" and args and args[0].get("strlit") \
                           and not args[0].get("concat") and a is not args[0]:
                            continue
                        for tok in at:
                            if tok.startswith("p:"):
                                summ["param_to_sink"].add(tok[2:])
                        if "SRC" in at:
                            local_find.append((cat, fk, func.get("pos"),
                                               call.get("line"), call.get("full"),
                                               hit["note"], hit["conf"], hit["origin"]))
                            break
                # (2) a call to an internal callee whose param reaches a sink
                for k in self.cg.resolve_callees(fk, call):
                    s = self.summaries.get((k, cat))
                    if not s or not s["param_to_sink"]:
                        continue
                    for b in self.cg._bind(k, call):
                        if b["param"] not in s["param_to_sink"]:
                            continue
                        at = self._tokens(fk, args[b["arg"]], cat, var_tokens)
                        if "SRC" in at:
                            local_find.append((cat, k, None, call.get("line"),
                                               "→ " + k, "via " + fk, 0.9, "summary"))
                        for tok in at:
                            if tok.startswith("p:"):
                                summ["param_to_sink"].add(tok[2:])
        summ["self_findings"] = local_find
        return summ

    def _best_sink(self, call, cat):
        from engine import _match
        matches = [s for s in self.az.sinks(cat) if _match(s["m"], call)]
        if not matches:
            return None
        prio = {"kb": 2, "generic": 1}
        return max(matches, key=lambda s: (prio.get(s["origin"], 0), s["conf"]))

    # ---- global monotone fixpoint over all functions ----
    def run(self):
        for cat in self.cats:
            for f in self.az.funcs:
                self.summaries.setdefault((f["key"], cat),
                    {"param_to_return": set(), "src_to_return": False,
                     "param_to_sink": set(), "self_findings": []})
        changed, rounds = True, 0
        while changed and rounds < 60:
            changed, rounds = False, rounds + 1
            for cat in self.cats:
                for f in self.az.funcs:
                    new = self._summarize(f, cat)
                    old = self.summaries[(f["key"], cat)]
                    if (new["param_to_return"] != old["param_to_return"] or
                            new["src_to_return"] != old["src_to_return"] or
                            new["param_to_sink"] != old["param_to_sink"]):
                        changed = True
                    self.summaries[(f["key"], cat)] = new
        # collect findings (deduped)
        seen = set()
        for (fk, cat), s in self.summaries.items():
            for fnd in s["self_findings"]:
                key = (fnd[0], fnd[1], fnd[3], fnd[4])
                if key in seen:
                    continue
                seen.add(key)
                self.findings.append({
                    "category": fnd[0], "func": fnd[1], "pos": fnd[2],
                    "line": fnd[3], "sink": fnd[4], "note": fnd[5],
                    "confidence": fnd[6], "origin": fnd[7]})
        return self.summaries, self.findings

    def dump(self):
        out = {}
        for (fk, cat), s in sorted(self.summaries.items()):
            if not (s["param_to_return"] or s["src_to_return"] or s["param_to_sink"]):
                continue
            out.setdefault(fk, {})[cat] = {
                "param→return": sorted(s["param_to_return"]),
                "src→return": s["src_to_return"],
                "param→sink": sorted(s["param_to_sink"]),
            }
        return out
