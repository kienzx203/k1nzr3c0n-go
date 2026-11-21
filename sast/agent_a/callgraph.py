"""
Agent A — explicit call graph.

Connects ALL functions: every function is a node; every call site becomes an
edge caller→callee with a full argument→parameter binding (positional, with
variadic absorption). Edge resolution:

  typed    : receiver type resolved by go/types  (x.M() with x : *T  →  T.M)
  by-name  : plain function foo()  →  func foo
  by-name? : method x.M() whose receiver type is unknown → every method named M
  unresolved: external/stdlib pkg call or dynamic dispatch (interface / func value)

Unresolved internal-looking calls are kept in a coverage ledger (taint-breaks)
so nothing is silently dropped.
"""

import irutil


class CallGraph:
    def __init__(self, ir, ssa_edges=None):
        self.funcs = ir.get("functions") or []
        self.nodes = {}            # key -> node dict
        self.edges = []            # list of edge dicts
        self.callee_lookup = {}    # (caller_key, line, callee_name) -> set(callee_keys)
        self.unresolved = []       # coverage ledger
        self._plain = {}           # name -> [keys]   (funcs with no receiver)
        self._methods = {}         # name -> [keys]   (methods)
        self._typed = {}           # (recvType,name) -> [keys]
        self._fileline = {}        # (file,line) -> [keys]  (func decl positions)
        self._override = {}        # (site_file,site_line,callee) -> (set(keys), dynamic)
        self.ssa_algo = None       # 'vta' | 'cha' | None
        self._build_nodes()
        if ssa_edges is not None:
            self._load_ssa(ssa_edges)
        self._build_edges()

    @staticmethod
    def _pos_fileline(pos):
        if not pos or ":" not in pos:
            return None
        parts = pos.rsplit(":", 2)
        try:
            return (parts[0], int(parts[1]))
        except (ValueError, IndexError):
            return None

    def _load_ssa(self, edges):
        """Build the SSA override map: precise callee set per call site."""
        for f in self.funcs:
            fl = self._pos_fileline(f.get("pos"))
            if fl:
                self._fileline.setdefault(fl, []).append(f["key"])
        # keyed by call SITE (file,line); the callee name is only a hint because
        # SSA names closures/func-values differently from the AST call text
        # (e.g. SSA 'viaClosure$1' vs AST variable 'f').
        for e in edges:
            cfl = self._pos_fileline(e.get("callee_pos"))
            keys = self._fileline.get(cfl) if cfl else None
            if not keys:
                self._ssa_unmapped = getattr(self, "_ssa_unmapped", 0) + 1
                continue
            k = (e.get("site_file"), e.get("site_line"))
            self._override.setdefault(k, []).append(
                {"name": e.get("callee_name"), "keys": set(keys),
                 "dynamic": bool(e.get("dynamic"))})

    def _build_nodes(self):
        for f in self.funcs:
            key = f["key"]
            params = f.get("paramNames") or []
            variadic = bool(f.get("params") and f["params"][-1].get("variadic"))
            node = {
                "key": key, "name": f["name"], "recvType": f.get("recvType", ""),
                "params": params, "params_full": f.get("params") or [],
                "variadic": variadic, "results": len(f.get("results") or []),
                "pkg": f.get("pkg", ""), "pos": f.get("pos", ""),
                "callers": set(), "callees": set(),
            }
            self.nodes[key] = node
            name = f["name"]
            if f.get("recvType"):
                self._methods.setdefault(name, []).append(key)
                self._typed.setdefault((f["recvType"].lstrip("*"), name), []).append(key)
            else:
                self._plain.setdefault(name, []).append(key)

    def _resolve(self, call, anon_vars=None, site_file=None):
        """Return (callee_keys, resolution_kind). SSA override wins when present."""
        name = call.get("callee") or ""
        recv = call.get("recv") or ""
        recvType = (call.get("recvType") or "").lstrip("*")
        anon_vars = anon_vars or {}
        if site_file and self._override:
            entries = self._override.get((site_file, call.get("line")))
            if entries:
                exact = [en for en in entries if en["name"] == name]
                use = exact if exact else entries  # name is a hint, not required
                keys, dyn = set(), False
                for en in use:
                    keys |= en["keys"]
                    dyn = dyn or en["dynamic"]
                if keys:
                    return list(keys), ("ssa-dynamic" if dyn else "ssa")
        # closure: direct func-literal call (IIFE) whose callee is an anon key,
        # or a call through a local variable bound to a func literal.
        if name in self.nodes and "$func" in name:
            return [name], "closure"
        if recv == "" and name in anon_vars:
            return [anon_vars[name]], "closure"
        if recvType and (recvType, name) in self._typed:
            return self._typed[(recvType, name)], "typed"
        if recv == "" and name in self._plain:
            return self._plain[name], "by-name"
        # bare call that matches a METHOD name = intra-class sibling call in a
        # frontend without type inference (e.g. `runQuery(x)` inside the class).
        # Resolve it (over-approximate, recall-first) so interproc flows hold.
        if recv == "" and name in self._methods:
            return self._methods[name], "by-name?"
        if recv != "" and name in self._methods:
            return self._methods[name], "by-name?"
        # B2: pkg.Func where Func is a USER function in another package
        if recv != "" and not recvType and name in self._plain:
            return self._plain[name], "cross-pkg?"
        return [], "unresolved"

    # External library calls are handled by the taint SPEC (source/sink/sanitizer),
    # so they are NOT taint-breaks. Only genuinely unknown user targets are.
    _REAL_BREAK = {"unknown-func", "dynamic/interface"}
    _BUILTINS = {"append", "cap", "close", "complex", "copy", "delete", "imag",
                 "len", "make", "new", "panic", "print", "println", "real", "recover"}

    def _unresolved_reason(self, call):
        recv = call.get("recv") or ""
        recvType = call.get("recvType") or ""
        full = call.get("full") or ""
        name = call.get("callee") or ""
        if recv and not recvType:
            return "external-pkg"      # pkg.Func (fmt/os/exec/http/...), spec-handled
        if recv and recvType:
            return "library-method"    # method on external type (Request/DB/Cmd), spec-handled
        if not recv and "." in full:
            return "library-chain"     # x.y().M() on a library result, spec-handled
        if name in self._BUILTINS:
            return "builtin"           # append/len/make/... — not a flow break
        return "unknown-func"          # bare call not resolved to any user func = real miss risk

    def _bind(self, callee_key, call):
        """argument index -> parameter name (positional, variadic-aware)."""
        node = self.nodes.get(callee_key)
        if not node:
            return []
        params = node["params"]
        variadic = node["variadic"]
        out = []
        for i, _arg in enumerate(call.get("args") or []):
            if i < len(params):
                out.append({"arg": i, "param": params[i]})
            elif variadic and params:
                out.append({"arg": i, "param": params[-1]})  # absorbed by ...T
        return out

    def _anon_vars(self, func):
        """Local variables bound to a func literal: var -> anon func key."""
        m = {}
        for op in func.get("ops") or []:
            if op.get("op") == "assign" and op.get("rhs") and op["rhs"].get("anon"):
                lhs = op.get("lhs") or []
                if len(lhs) == 1:
                    m[lhs[0]] = op["rhs"]["anon"]
        return m

    def _build_edges(self):
        for f in self.funcs:
            caller = f["key"]
            anon_vars = self._anon_vars(f)
            fl = self._pos_fileline(f.get("pos"))
            site_file = fl[0] if fl else None
            for call in irutil.func_calls(f):
                keys, kind = self._resolve(call, anon_vars, site_file)
                if not keys:
                    self.unresolved.append({
                        "caller": caller, "call": call.get("full"),
                        "line": call.get("line"), "reason": self._unresolved_reason(call)})
                    continue
                lk = (caller, call.get("line"), call.get("callee"))
                self.callee_lookup.setdefault(lk, set()).update(keys)
                for ck in keys:
                    self.nodes[caller]["callees"].add(ck)
                    self.nodes[ck]["callers"].add(caller)
                    self.edges.append({
                        "caller": caller, "callee": ck, "line": call.get("line"),
                        "resolution": kind, "bindings": self._bind(ck, call),
                        "full": call.get("full"),
                    })

    # ---- consumers / exports ----
    def resolve_callees(self, caller_key, call):
        return self.callee_lookup.get(
            (caller_key, call.get("line"), call.get("callee")), set())

    def stats(self):
        roots = [k for k, n in self.nodes.items() if not n["callers"]]
        leaves = [k for k, n in self.nodes.items() if not n["callees"]]
        by_kind = {}
        for e in self.edges:
            by_kind[e["resolution"]] = by_kind.get(e["resolution"], 0) + 1
        ur = {}
        for u in self.unresolved:
            ur[u["reason"]] = ur.get(u["reason"], 0) + 1
        breaks = sum(1 for u in self.unresolved if u["reason"] in self._REAL_BREAK)
        return {
            "functions": len(self.nodes), "edges": len(self.edges),
            "resolved_by": by_kind, "unresolved": len(self.unresolved),
            "unresolved_by": ur, "taint_breaks": breaks,
            "roots": len(roots), "leaves": len(leaves),
        }

    def to_dict(self):
        return {
            "nodes": [{k: (sorted(v) if isinstance(v, set) else v)
                       for k, v in n.items()} for n in self.nodes.values()],
            "edges": self.edges,
            "unresolved": self.unresolved,
            "stats": self.stats(),
        }

    def to_dot(self):
        lines = ["digraph callgraph {", '  rankdir=LR;',
                 '  node [shape=box, fontname="monospace", fontsize=10];']
        for k, n in self.nodes.items():
            sig = f'{n["name"]}({", ".join(n["params"])})'
            shape = "box"
            if not n["callers"]:
                shape = "box, style=filled, fillcolor=\"#cde7ff\""  # root/entry
            lines.append(f'  "{k}" [label="{sig}", {shape}];')
        style = {"typed": "solid", "by-name": "solid",
                 "by-name?": "dashed", "unresolved": "dotted"}
        for e in self.edges:
            lab = ",".join(b["param"] for b in e["bindings"])
            ls = style.get(e["resolution"], "solid")
            color = "#999999" if e["resolution"].startswith("by-name?") else "#333333"
            lines.append(f'  "{e["caller"]}" -> "{e["callee"]}" '
                         f'[label="{lab}", style={ls}, color="{color}"];')
        lines.append("}")
        return "\n".join(lines)
