#!/usr/bin/env python3
"""#2 — statement-level def->use flow reconstruction (Checkmarx-style source→…→sink
path). ADDITIVE: does not change taint decisions; given a finding (func, sink line,
tainted arg) it walks DEF→USE backward through the IR — intra-procedurally over
assignments and inter-procedurally from a parameter back to the caller's argument —
to produce the ordered path the engine already decided is tainted.
"""
import irutil


def _vars(e):
    return list(e.get("idents") or []) if isinstance(e, dict) else []


def _source_in(az, e):
    if not isinstance(e, dict):
        return None
    for c in e.get("calls") or []:
        s = az.is_source(c)
        if s:
            return c.get("full") or c.get("callee") or "source"
    return None


def _func_defs(f):
    """var -> list of (line, rhs_expr) assignments, in order."""
    defs = {}
    for op in f.get("ops") or []:
        if op.get("op") == "assign":
            for v in op.get("lhs") or []:
                defs.setdefault(v, []).append((op.get("line"), op.get("rhs")))
    return defs


def _callsites(ir, cg):
    """callee_key -> list of (caller_key, line, call_expr) resolved via the graph."""
    sites = {}
    for f in ir.get("functions") or []:
        fk = f["key"]
        for op in f.get("ops") or []:
            for call in irutil.all_calls(op):
                for ck in cg.resolve_callees(fk, call) or []:
                    sites.setdefault(ck, []).append((fk, op.get("line"), call))
    return sites


def build(az, ir, cg, finding, max_depth=60, sites=None, by_key=None):
    # `sites`/`by_key` are whole-program indexes; building them per finding is
    # O(findings × program size) (quadratic). The caller passes them in, built once.
    if by_key is None:
        by_key = {f["key"]: f for f in ir.get("functions") or []}
    if sites is None:
        sites = _callsites(ir, cg)
    fk, sink_line = finding.get("func"), finding.get("line")
    func = by_key.get(fk)
    if not func:
        return []
    # tainted argument variables at the sink call
    sink_vars = []
    for op in func.get("ops") or []:
        if op.get("line") == sink_line:
            for c in irutil.all_calls(op):
                for a in c.get("args") or []:
                    sink_vars += _vars(a)
    path, seen = [], set()

    def trace(fkey, var, depth):
        if depth > max_depth or (fkey, var) in seen:
            return
        seen.add((fkey, var))
        fn = by_key.get(fkey)
        if not fn:
            return
        # 1. nearest definition
        defs = _func_defs(fn).get(var, [])
        if defs:
            line, rhs = list(reversed(defs))[0]
            src = _source_in(az, rhs)
            if src:
                path.append({"func": fkey, "line": line, "role": "source",
                             "var": var, "desc": "%s = %s" % (var, src)})
                return
            if _vars(rhs) or rhs.get("calls"):
                path.append({"func": fkey, "line": line, "role": "step",
                             "var": var, "desc": "%s = …" % var})
                for v in _vars(rhs):
                    trace(fkey, v, depth + 1)
                for c in rhs.get("calls") or []:
                    if c.get("recv"):                       # obj.method() -> follow the object
                        trace(fkey, c["recv"], depth + 1)
                    for ck in cg.resolve_callees(fkey, c) or []:
                        for rp in (by_key.get(ck, {}).get("paramNames") or []):
                            trace(ck, rp, depth + 1)
        # 2. receiver-mutation — ALWAYS (taint can enter via var.method(tainted) even
        #    when `var` has a benign def like `new Builder()`).
        for op in fn.get("ops") or []:
            for c in irutil.all_calls(op):
                if c.get("recv") == var:
                    for a in c.get("args") or []:
                        s2 = _source_in(az, a)
                        if _vars(a) or s2:
                            path.append({"func": fkey, "line": op.get("line"), "role": "step",
                                         "var": var, "desc": "%s.%s(…)" % (var, c.get("callee") or "")})
                            for v in _vars(a):
                                trace(fkey, v, depth + 1)
                            if s2:
                                path.append({"func": fkey, "line": op.get("line"), "role": "source",
                                             "var": var, "desc": s2})
        # 3. parameter -> follow back to the caller's argument (only when no local def)
        params = fn.get("paramNames") or []
        if not defs and var in params:
            idx = params.index(var)
            for caller, line, call in sites.get(fkey, [])[:4]:
                args = call.get("args") or []
                if idx < len(args):
                    path.append({"func": caller, "line": line, "role": "call",
                                 "var": var, "desc": "→ %s(arg %d)" % (fn.get("name", fkey), idx)})
                    for v in _vars(args[idx]):
                        trace(caller, v, depth + 1)
                    if _source_in(az, args[idx]):
                        path.append({"func": caller, "line": line, "role": "source",
                                     "var": var, "desc": _source_in(az, args[idx])})
                    break

    # append sink FIRST — the trace then adds steps backward (sink→source), and a
    # final reverse yields source→…→sink.
    path.append({"func": fk, "line": sink_line, "role": "sink",
                 "desc": finding.get("sink") or "sink"})
    for v in sink_vars:
        trace(fk, v, 0)
    path.reverse()
    out = []
    for p in path:
        if not out or (out[-1].get("line"), out[-1].get("func")) != (p.get("line"), p.get("func")):
            out.append(p)
    return out
