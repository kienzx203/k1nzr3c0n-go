#!/usr/bin/env python3
"""
Agent A — universal tree-sitter extractor framework.

Emits the SAME IR JSON as agent_a/go_extract so the existing language-agnostic
call graph (callgraph.py) + taint engine (engine.py) + summaries work unchanged
for ANY language. Each language is a small plugin under plugins/<lang>.py that
maps that grammar's node types to roles; this file is the generic driver.

    python3 extract.py <lang> <dir>      # prints IR JSON on stdout

IR schema (per function):
  {key,name,recvType,params:[{name}],paramNames:[...],results:[],pkg,pos,anonymous,ops:[...]}
ops: {op:assign|call|return|expr, line, lhs:[], rhs:Expr, call:CallExpr, values:[Expr]}
Expr: {idents:[],concat:bool,strlit:bool,calls:[CallExpr],anon:str}
CallExpr: {callee,recv,recvType,full,args:[Expr],line}
"""
import importlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from tree_sitter_language_pack import get_parser  # noqa: E402


def txt(n, src):
    return src[n.start_byte:n.end_byte].decode("utf-8", "replace")


import re as _re
_LOOP_RE = _re.compile(r"(?:^|_)(for|foreach|while|loop|repeat|do)(?:_|$)", _re.I)
_BRANCH_RE = _re.compile(r"(if|else|elif|switch|case|when|try|catch|except|finally|guard|cond|match_|ternary|conditional)", _re.I)


def pos(n, path):
    return f"{path}:{n.start_point[0] + 1}:{n.start_point[1] + 1}"


def _member_text(c, node, src):
    """Field-sensitive taint key for a member access: plugin member_path() if
    defined, else the normalized node text (obj.field / obj->field)."""
    mp = getattr(c, "member_path", None)
    if mp is not None:
        r = mp(node, src)
        if r:
            return r
    return " ".join(txt(node, src).split())


def _member_lhs(c, node, src, lhs):
    """If an assignment's LHS is a member access, use its dotted path as the taint
    key (field-sensitive) instead of the base object a plugin may have returned."""
    mt = getattr(c, "MEMBER_TYPES", set())
    if not mt:
        return lhs
    left = node.child_by_field_name("left") or node.child_by_field_name("name")
    if left is None and node.named_children:
        left = node.named_children[0]
    if left is not None and left.type in mt:
        mp = _member_text(c, left, src)
        if mp:
            return [mp]
    return lhs


def load_plugin(lang):
    return importlib.import_module(f"plugins.{lang}")


class Extractor:
    def __init__(self, cfg, src, path, pkg):
        self.c = cfg
        self.src = src
        self.path = path
        self.pkg = pkg
        self.funcs = []
        self.call_seen = 0
        self.anon = {}
        self.cur_fk = ""   # current enclosing function key (for closure parent)

    # ---------- expression analysis ----------
    def expr(self, node, depth=0):
        info = {"idents": [], "concat": False, "strlit": False, "calls": []}
        if node is None or depth > 60:
            return info
        # arg-structure flags for Semgrep patterns: `$_ * $_` -> mul, `&$VAR` -> addr.
        _s = txt(node, self.src)
        _ns = _re.sub(r"'[^']*'|\"[^\"]*\"", " ", _s)
        if _re.search(r"[\w)\]]\s*\*\s*[\w(&]", _ns):
            info["mul"] = True
        if _s.lstrip().startswith("&"):
            info["addr"] = True
        seen = set()
        c = self.c

        def rec(n):
            t = n.type
            if t in c.CALL_TYPES:
                info["calls"].append(self.call(n))
                # descend into the RECEIVER side only (chained calls like a().b());
                # argument-position calls/idents are already captured inside
                # self.call() via expr(arg), so skipping "argument*" children keeps
                # call_seen == call_total (no double counting).
                for ch in n.children:
                    if "argument" in ch.type:
                        continue
                    rec(ch)
                return
            if t in c.LAMBDA_TYPES:
                saved = self.cur_fk
                info["anon"] = self.build_func(n, anon=True, parent=self.cur_fk)
                self.cur_fk = saved
                return
            if t in c.STRING_TYPES:
                info["strlit"] = True
            if t in getattr(c, "INTERP_TYPES", set()):
                info["concat"] = True
            if t in getattr(c, "BINARY_TYPES", set()) and c.is_concat(n, self.src):
                info["concat"] = True
            # #3 field-sensitivity: emit a member access as a dotted path
            # (obj.field) so distinct fields are distinct taint keys; don't
            # descend (avoid also emitting the bare base identifier).
            if t in getattr(c, "MEMBER_TYPES", set()):
                mp = _member_text(c, n, self.src)
                if mp:
                    if mp not in seen:
                        seen.add(mp)
                        info["idents"].append(mp)
                    return
            if t in c.IDENT_TYPES:
                v = txt(n, self.src)
                if v and v not in seen:
                    seen.add(v)
                    info["idents"].append(v)
            for ch in n.children:
                rec(ch)

        rec(node)
        return info

    def call(self, node):
        self.call_seen += 1
        callee, recv, args = self.c.call_parts(node, self.src)
        full = (recv + "." + callee) if recv else callee
        return {"callee": callee or "", "recv": recv or "", "recvType": "",
                "full": full or "?", "line": node.start_point[0] + 1,
                "args": [self.expr(a) for a in args]}

    # ---------- function / op building ----------
    def build_func(self, node, anon=False, recvtype="", parent=""):
        c = self.c
        name = "" if anon else c.func_name(node, self.src)
        if anon:
            n = self.anon.get(parent, 0) + 1
            self.anon[parent] = n
            key = f"{parent}$func{n}"
            name = key
        else:
            base = (self.pkg + "." if self.pkg else "")
            if recvtype:
                base += recvtype + "."
            key = base + (name or "anon")
        _sp = getattr(c, "source_params", None)
        f = {"key": key, "name": name, "recvType": recvtype,
             "params": [{"name": p} for p in c.func_params(node, self.src)],
             "paramNames": c.func_params(node, self.src), "results": [],
             # params that are untrusted-input by a framework annotation (e.g. Spring
             # @RequestParam / @PathVariable / @RequestBody) — seeded as sources.
             "source_params": (_sp(node, self.src) if _sp else []),
             "pkg": self.pkg, "pos": pos(node, self.path),
             "anonymous": anon, "ops": []}
        self.funcs.append(f)
        body = c.func_body(node)
        if body is not None:
            f["ops"] = self.build_ops(body, key)
        return key

    def build_ops(self, body, fk, module_mode=False):
        c = self.c
        ops = []
        self.cur_fk = fk
        stop = c.FUNC_TYPES | c.LAMBDA_TYPES
        foreach = getattr(c, "FOREACH_TYPES", set())
        loop_depth = [0]   # ops built while >0 are inside a loop body (CFG back-edge)
        branch_depth = [0] # inside an if/else/switch/try branch (join = union: no kill)

        def walk(n):
            t = n.type
            inloop = loop_depth[0] > 0
            inbranch = branch_depth[0] > 0
            if t in c.ASSIGN_TYPES:
                lhs, rhs_nodes = c.assign_parts(n, self.src)
                lhs = _member_lhs(c, n, self.src, lhs)   # field-sensitive member LHS
                merged = {"idents": [], "concat": False, "strlit": False, "calls": []}
                s = set()
                for rn in rhs_nodes:
                    e = self.expr(rn)
                    merged["concat"] |= e["concat"]
                    merged["strlit"] |= e["strlit"]
                    merged["calls"] += e["calls"]
                    if e.get("anon"):
                        merged["anon"] = e["anon"]
                    for i in e["idents"]:
                        if i not in s:
                            s.add(i)
                            merged["idents"].append(i)
                # capture CALLS embedded in the LHS (not its taint) — e.g. a write
                # `buf[taintedIndex] = x` surfaces an __arr_index__ sink for OOB-write,
                # and `obj[f()] = x` / `a.m()[i] = x` keep their calls visible.
                _left = n.child_by_field_name("left")
                if _left is not None and _left.type not in ("identifier", "variable_name"):
                    merged["calls"] += self.expr(_left)["calls"]
                ops.append({"op": "assign", "line": n.start_point[0] + 1,
                            "lhs": lhs, "rhs": merged, "loop": inloop, "branch": inbranch})
                return
            if t in c.RETURN_TYPES:
                ops.append({"op": "return", "line": n.start_point[0] + 1,
                            "values": [self.expr(v) for v in c.return_vals(n)], "loop": inloop, "branch": inbranch})
                return
            if t in c.CALL_TYPES:
                ops.append({"op": "expr", "line": n.start_point[0] + 1,
                            "rhs": self.expr(n), "loop": inloop, "branch": inbranch})
                return
            if t in stop:
                if module_mode and t in c.FUNC_TYPES:
                    return
                saved = self.cur_fk
                # a nested NAMED function (def inner(): …) keeps its real name so a call
                # to it resolves by name; only truly anonymous closures/lambdas get a
                # synthetic $funcN key.
                named_nested = (t in c.FUNC_TYPES) and bool(c.func_name(n, self.src))
                self.build_func(n, anon=not named_nested, parent=fk)  # nested func/lambda
                self.cur_fk = saved                       # restore for siblings
                return
            if t in foreach:
                vn, it = c.foreach_parts(n, self.src)
                if vn and it is not None:
                    ops.append({"op": "assign", "line": n.start_point[0] + 1,
                                "lhs": vn, "rhs": self.expr(it), "loop": True})
            is_loop = bool(_LOOP_RE.search(t)) or t in foreach
            is_branch = bool(_BRANCH_RE.search(t))
            if is_loop:
                loop_depth[0] += 1
            if is_branch:
                branch_depth[0] += 1
            for ch in n.children:
                walk(ch)
            if is_loop:
                loop_depth[0] -= 1
            if is_branch:
                branch_depth[0] -= 1

        # If a grammar has no distinct body node (e.g. VB method_declaration holds
        # its statements as direct children), func_body returns the func node
        # itself; walk its CHILDREN so the root isn't re-detected as a nested func.
        if body.type in stop:
            for ch in body.children:
                walk(ch)
        else:
            walk(body)
        return ops

    def run(self, root):
        c = self.c

        def walk(n, recvtype):
            t = n.type
            if t in c.FUNC_TYPES:
                self.build_func(n, anon=False, recvtype=recvtype)
                return  # its body (incl. nested funcs) handled in build_func
            nt = recvtype
            if t in getattr(c, "CLASS_TYPES", set()):
                nt = c.class_name(n, self.src) or recvtype
            for ch in n.children:
                walk(ch, nt)

        walk(root, "")

        # synthetic <module> function: captures TOP-LEVEL code (module-scope
        # statements, lambdas/closures, and taint flows) that live outside any
        # named function. Named funcs are built by walk() above; module_mode
        # build_ops skips them and only builds module-level lambdas/ops.
        mod_key = (self.pkg + "." if self.pkg else "") + "<module>"
        self.cur_fk = mod_key
        mod_ops = self.build_ops(root, mod_key, module_mode=True)
        if mod_ops:
            self.funcs.append({
                "key": mod_key, "name": "<module>", "recvType": "",
                "params": [], "paramNames": [], "results": [], "pkg": self.pkg,
                "pos": f"{self.path}:1:1", "anonymous": False, "ops": mod_ops})


def main():
    # deeply-nested code recurses in build_ops/build_func; raise the limit so a big
    # (but valid) file does not throw RecursionError and lose its functions.
    sys.setrecursionlimit(13000)
    lang, root = sys.argv[1], sys.argv[2]
    cfg = load_plugin(lang)
    parser = get_parser(cfg.TS_LANG)
    out = {"dir": root, "functions": [], "call_seen": 0, "call_total": 0}
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in ("vendor", "node_modules", ".git")]
        for fn in fns:
            if not any(fn.endswith(e) for e in cfg.EXTS):
                continue
            path = os.path.join(dp, fn)
            try:
                src = open(path, "rb").read()
            except OSError:
                continue
            # ISOLATE per file: one pathological file (recursion/parse blowup) must
            # never abort extraction of the whole target and drop every other file.
            try:
                tree = parser.parse(src)
                pkg = cfg.pkg_name(tree.root_node, src, path)
                ex = Extractor(cfg, src, path, pkg)
                ex.run(tree.root_node)
                out["functions"] += ex.funcs
                out["call_seen"] += ex.call_seen
                out["call_total"] += count_calls(tree.root_node, cfg.CALL_TYPES)
            except RecursionError:
                sys.stderr.write("extract: skipped (too deeply nested): %s\n" % path)
            except Exception as e:  # noqa: BLE001
                sys.stderr.write("extract: skipped (%s): %s\n" % (type(e).__name__, path))
    # unique keys
    seen = {}
    for f in out["functions"]:
        k = f["key"]
        if k in seen:
            seen[k] += 1
            f["key"] = f"{k}#{seen[k]}"
        else:
            seen[k] = 0
    json.dump(out, sys.stdout, ensure_ascii=False)


def count_calls(root, call_types):
    n = 0
    stack = [root]
    while stack:
        x = stack.pop()
        if x.type in call_types:
            n += 1
        stack.extend(x.children)
    return n


if __name__ == "__main__":
    main()
