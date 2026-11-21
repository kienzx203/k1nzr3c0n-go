#!/usr/bin/env python3
"""Lightweight structural extractor for languages without a (usable) tree-sitter
grammar: PL/SQL, VB6/VBScript, COBOL. Produces the SAME IR as ts_extract
(functions with ops: assign/call/return; Expr: idents/concat/strlit/calls) so the
call graph + taint engine + summaries work unchanged.

Not a full parser — a statement/verb oriented reader tuned for taint (who calls
what, what flows into what). Adequate for SAST_k1nz's coarse IR; a full ANTLR
grammar would be the higher-fidelity upgrade.
"""
import os
import re

_WORD = r"[A-Za-z_][\w.$-]*"
_CALL = re.compile(r"(" + _WORD + r")\s*\(")
_STR = re.compile(r"'[^']*'|\"[^\"]*\"")

# keywords we never treat as a tainted identifier (per family, lowercased)
_KW = {
    "plsql": {"select", "from", "where", "and", "or", "into", "values", "set",
              "begin", "end", "if", "then", "else", "elsif", "loop", "for", "while",
              "is", "as", "declare", "return", "null", "not", "in", "out", "exec",
              "execute", "immediate", "procedure", "function", "cursor", "open",
              "fetch", "close", "update", "insert", "delete", "table", "using",
              "like", "between", "order", "by", "group", "having", "union", "to",
              "number", "varchar2", "varchar", "integer", "boolean", "date", "type"},
    "vb": {"dim", "set", "as", "new", "if", "then", "else", "elseif", "end", "for",
           "next", "each", "while", "wend", "do", "loop", "sub", "function", "call",
           "return", "nothing", "true", "false", "and", "or", "not", "byval", "byref",
           "string", "integer", "object", "variant", "boolean", "public", "private",
           "class", "property", "get", "let", "optional", "with", "select", "case"},
    "cobol": {"move", "to", "from", "call", "using", "perform", "if", "then", "else",
              "end-if", "compute", "string", "into", "exec", "sql", "end-exec",
              "display", "accept", "program-id", "procedure", "division", "section",
              "working-storage", "pic", "picture", "value", "end", "stop", "run",
              "and", "or", "not", "giving", "by", "reference", "content", "of"},
}


def _strip_strings(s):
    return _STR.sub(" ", s)


def _balanced(s, open_idx):
    depth, i = 0, open_idx
    while i < len(s):
        if s[i] == "(":
            depth += 1
        elif s[i] == ")":
            depth -= 1
            if depth == 0:
                return s[open_idx + 1:i]
        i += 1
    return s[open_idx + 1:]


def _split_args(s):
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur); cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return out


def parse_expr(text, fam, line=0):
    e = {"idents": [], "concat": False, "strlit": False, "calls": []}
    if not text:
        return e
    if _STR.search(text):
        e["strlit"] = True
    concat_op = {"plsql": "||", "vb": "&", "cobol": "delimited"}.get(fam, "+")
    if concat_op in text or "+" in text:
        e["concat"] = True
    bare = _strip_strings(text)
    kw = _KW.get(fam, set())
    callnames = set()
    for m in _CALL.finditer(bare):
        name = m.group(1)
        if name.lower() in kw:
            continue
        args_txt = _balanced(bare, m.end() - 1)
        recv, callee = ("", name)
        if "." in name:
            recv, callee = name.rsplit(".", 1)
        callnames.add(callee); callnames.add(recv)
        e["calls"].append({"callee": callee, "recv": recv, "recvType": "",
                           "full": (recv + "." + callee) if recv else callee,
                           "args": [parse_expr(a, fam, line) for a in _split_args(args_txt)],
                           "line": line})
    for w in re.findall(_WORD, bare):
        base = w.split(".")[0]
        if base in callnames or w in callnames:
            continue
        if w.lower() in kw or base.lower() in kw:
            continue
        if re.fullmatch(r"[\d.]+", w):
            continue
        if w not in e["idents"]:
            e["idents"].append(w)
    return e


# ---------------- PL/SQL ----------------
_PLSQL_FUNC = re.compile(r"\b(?:PROCEDURE|FUNCTION)\s+(\w+)\s*(\(([^)]*)\))?", re.I)
_PLSQL_ASSIGN = re.compile(r"^\s*(\w+)\s*:=\s*(.+?);", re.I)
_PLSQL_EXECIMM = re.compile(r"\bEXECUTE\s+IMMEDIATE\s+(.+?);", re.I)


_PARAM_MODS = {"byval", "byref", "optional", "paramarray", "ref", "const",
               "in", "out", "inout", "value", "reference"}


def _params(txt):
    """Parameter names for VB/PL-SQL/COBOL. Skips leading modifier keywords
    (VB `ByVal name` must yield `name`, not `ByVal`) and keeps hyphenated COBOL
    names (`WS-NAME` stays whole, not split to `WS`)."""
    if not txt:
        return []
    out = []
    for p in txt.split(","):
        name = None
        for tk in re.findall(r"[A-Za-z_][\w-]*", p):
            if tk.lower() in _PARAM_MODS:
                continue
            name = tk
            break
        if name:
            out.append(name)
    return out


def extract_plsql(src_dir):
    funcs = []
    for path in _files(src_dir, (".sql", ".pks", ".pkb", ".pls", ".plsql")):
        src = _read(path)
        pkg = os.path.splitext(os.path.basename(path))[0]
        # split into function bodies by PROCEDURE/FUNCTION ... (crude: each decl starts a func)
        decls = list(_PLSQL_FUNC.finditer(src))
        if not decls:
            decls = [None]
        for i, d in enumerate(decls):
            if d is None:
                name, params, start = "<main>", [], 0
                end = len(src)
            else:
                name = d.group(1); params = _params(d.group(3) or "")
                start = d.end()
                end = decls[i + 1].start() if i + 1 < len(decls) else len(src)
            body = src[start:end]
            line0 = src[:start].count("\n") + 1
            funcs.append(_mk(pkg, name, params, path, line0,
                             _plsql_ops(body, line0)))
    return {"dir": src_dir, "functions": funcs, "call_seen": 0, "call_total": 0}


def _strip_comments(text, fam):
    if fam == "plsql":
        text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
        text = re.sub(r"--[^\n]*", "", text)
    elif fam == "vb":
        text = re.sub(r"(?mi)^\s*REM\b[^\n]*", "", text)
        # VB apostrophe comments — but an apostrophe INSIDE a double-quoted string
        # is not a comment (SQL literals like "WHERE n = '"). Match a full string
        # first (keep it) so only a real trailing `'...` comment is removed.
        text = re.sub(r'"[^"\n]*"|(\'[^\n]*)',
                      lambda m: "" if m.group(1) else m.group(0), text)
    return text


def _statements(text):
    """Split into statements by ';' while keeping the source line of each."""
    out, start, line = [], 0, 1
    for i, ch in enumerate(text):
        if ch == "\n":
            line += 1
        elif ch == ";":
            seg = text[start:i]
            out.append((line - seg.count("\n"), seg))
            start = i + 1
    if text[start:].strip():
        seg = text[start:]
        out.append((line - seg.count("\n"), seg))
    return out


def _plsql_ops(body, line0):
    ops = []
    body = _strip_comments(body, "plsql")
    for sline, stmt in _statements(body):
        line = line0 + sline - 1
        flat = " ".join(stmt.split())
        m = re.search(r"(?:^|\s)(\w+)\s*:=\s*(.+)$", flat, re.I)
        if m:
            ops.append({"op": "assign", "line": line, "lhs": [m.group(1)],
                        "rhs": parse_expr(m.group(2), "plsql")})
            continue
        m = re.search(r"\bEXECUTE\s+IMMEDIATE\s+(.+)$", flat, re.I)
        if m:
            e = parse_expr(m.group(1), "plsql")
            e["calls"].insert(0, {"callee": "EXECUTE_IMMEDIATE", "recv": "", "recvType": "",
                                  "full": "EXECUTE IMMEDIATE", "args": [parse_expr(m.group(1), "plsql")],
                                  "line": line})
            ops.append({"op": "expr", "line": line, "rhs": e})
            continue
        # dynamic cursor: OPEN cur FOR <dynamic sql string/var>. A static query
        # (OPEN cur FOR SELECT ... / WITH ...) is NOT dynamic SQL -> not a sink.
        m = re.search(r"\bOPEN\s+\w+\s+FOR\s+(.+)$", flat, re.I)
        if m:
            rest = m.group(1).strip()
            if not re.match(r"(?i)(select|with)\b", rest):
                e = parse_expr(rest, "plsql")
                e["calls"].insert(0, {"callee": "OPEN_FOR", "recv": "", "recvType": "",
                                      "full": "OPEN FOR", "args": [parse_expr(rest, "plsql")],
                                      "line": line})
                ops.append({"op": "expr", "line": line, "rhs": e})
            continue
        m = re.match(r"\breturn\b\s*(.*)$", flat, re.I) or (re.search(r"\breturn\b\s*(.+)$", flat, re.I))
        if m:
            ops.append({"op": "return", "line": line,
                        "values": [parse_expr(m.group(1), "plsql")]})
            continue
        e = parse_expr(flat, "plsql")
        if e["calls"]:
            ops.append({"op": "expr", "line": line, "rhs": e})
    return ops


# ---------------- VB6 / VBScript ----------------
_VB_FUNC = re.compile(r"^\s*(?:Public\s+|Private\s+)?(?:Sub|Function)\s+(\w+)\s*(\(([^)]*)\))?", re.I)
_VB_END = re.compile(r"^\s*End\s+(?:Sub|Function)", re.I)
_VB_ASSIGN = re.compile(r"^\s*(?:Set\s+|Dim\s+)?([A-Za-z_]\w*)\s*=\s*(.+)$", re.I)
# VB file I/O statement: `Open <path> For <mode> As #n` (path traversal surface).
_VB_OPEN = re.compile(r"^\s*Open\s+(.+?)\s+For\s+(?:Input|Output|Append|Random|Binary)\b", re.I)
# Paren-less call statement: `[Call] Name[.Method] arg1, arg2`  (VB subs/methods are
# idiomatically invoked without parentheses, which the call-with-parens reader misses).
_VB_CALLSTMT = re.compile(r"^\s*(?:Call\s+)?([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s+(\S.*)$")
# statement keywords that look like `KW rest` but are NOT calls -> never a call stmt
_VB_STMT_KW = {"dim", "redim", "const", "static", "public", "private", "friend",
               "global", "option", "on", "exit", "goto", "gosub", "resume", "end",
               "stop", "declare", "type", "enum", "sub", "function", "property",
               "if", "elseif", "else", "for", "next", "do", "loop", "while", "wend",
               "select", "case", "with", "set", "let", "print", "write", "input",
               "line", "erase", "randomize", "close", "reset", "load", "unload",
               "debug", "attribute", "implements", "event", "raiseevent", "def",
               "rem", "get", "put", "open", "to", "then", "as", "new", "byval",
               "byref", "optional", "and", "or", "not", "is", "mod", "like"}


def extract_vb(src_dir):
    funcs = []
    for path in _files(src_dir, (".vbs", ".bas", ".cls", ".frm", ".asp")):
        src = _strip_comments(_read(path), "vb")
        src = re.sub(r"[ \t]_\r?\n[ \t]*", " ", src)   # VB line-continuation ` _`
        pkg = os.path.splitext(os.path.basename(path))[0]
        lines = src.splitlines()
        cur = None
        for ln, raw in enumerate(lines):
            line = ln + 1
            fm = _VB_FUNC.match(raw)
            if fm:
                cur = _mk(pkg, fm.group(1), _params(fm.group(3) or ""), path, line, [])
                funcs.append(cur)
                continue
            if _VB_END.match(raw):
                cur = None
                continue
            tgt = cur
            if tgt is None:
                # module-level
                tgt = next((f for f in funcs if f["name"] == "<main>"), None)
                if tgt is None:
                    tgt = _mk(pkg, "<main>", [], path, 1, []); funcs.append(tgt)
            _vb_stmt(raw, line, tgt["ops"])
    return {"dir": src_dir, "functions": funcs, "call_seen": 0, "call_total": 0}


def _vb_stmt(raw, line, ops):
    if re.search(r"\breturn\b", raw, re.I):
        ops.append({"op": "return", "line": line,
                    "values": [parse_expr(re.sub(r".*\breturn\b", "", raw, flags=re.I), "vb")]})
        return
    m = _VB_ASSIGN.match(raw)
    if m and not re.match(r"^\s*(If|For|While|Do|ElseIf)\b", raw, re.I):
        ops.append({"op": "assign", "line": line, "lhs": [m.group(1)],
                    "rhs": parse_expr(m.group(2), "vb")})
        return
    om = _VB_OPEN.match(raw)
    if om:
        ops.append({"op": "expr", "line": line,
                    "rhs": {"idents": [], "concat": False, "strlit": False,
                            "calls": [{"callee": "VB_FILE_OPEN", "recv": "", "recvType": "",
                                       "full": "VB_FILE_OPEN", "line": line,
                                       "args": [parse_expr(om.group(1), "vb")]}]}})
        return
    e = parse_expr(raw, "vb")
    if e["calls"]:
        ops.append({"op": "expr", "line": line, "rhs": e})
        return
    cm = _VB_CALLSTMT.match(raw)
    if cm:
        head = cm.group(1)
        base = head.split(".")[0].lower()
        last = head.split(".")[-1].lower()
        # keyword filter applies to the leading token; a dotted method call
        # (`rs.Open ...`) is always a call even if the method name is a keyword.
        if base not in _VB_STMT_KW and ("." in head or last not in _VB_STMT_KW):
            recv, callee = ("", head)
            if "." in head:
                recv, callee = head.rsplit(".", 1)
            args = [parse_expr(a, "vb") for a in _split_args(cm.group(2))]
            full = (recv + "." + callee) if recv else callee
            # ADO Recordset/Connection `.Open` -> VB-specific synthetic callee so a
            # SQLI sink can match it WITHOUT colliding with C#/VB.NET `.Open()`
            # (which is a parameterless connection-open, not SQL). Family is shared.
            emit = "ADODB_OPEN" if (recv and callee.lower() == "open") else callee
            ops.append({"op": "expr", "line": line,
                        "rhs": {"idents": [], "concat": False, "strlit": False,
                                "calls": [{"callee": emit, "recv": recv, "recvType": "",
                                           "full": full, "args": args, "line": line}]}})


# ---------------- COBOL ----------------
_COB_PROG = re.compile(r"\bPROGRAM-ID\.\s*([\w-]+)", re.I)
_COB_MOVE = re.compile(r"\bMOVE\s+(.+?)\s+TO\s+([\w-]+)", re.I)
_COB_COMPUTE = re.compile(r"\bCOMPUTE\s+([\w-]+)\s*=\s*(.+?)(?:\.|$)", re.I)
_COB_CALL = re.compile(r"\bCALL\s+(\S+)(?:\s+USING\s+(.+?))?(?:\.|$)", re.I)
_COB_EXECSQL = re.compile(r"\bEXEC\s+SQL\b(.+?)\bEND-EXEC", re.I | re.S)


def extract_cobol(src_dir):
    funcs = []
    for path in _files(src_dir, (".cob", ".cbl", ".cpy", ".cobol")):
        src = _read(path)
        # drop sequence-number columns (1-6) when fixed-format
        lines = [ln[6:] if len(ln) > 6 and ln[:6].strip().isdigit() else ln
                 for ln in src.splitlines()]
        body = "\n".join(lines)
        pm = _COB_PROG.search(body)
        name = pm.group(1) if pm else os.path.splitext(os.path.basename(path))[0]
        # PROCEDURE DIVISION USING p1 p2 … → the linkage parameters are the program's
        # (untrusted) input surface for a called sub-program / stored routine.
        um = re.search(r"\bPROCEDURE\s+DIVISION\s+USING\s+(.+?)\.", body, re.I | re.S)
        cob_params = [p for p in re.split(r"[\s,]+", um.group(1).strip()) if p and p.upper() != "BY"] if um else []
        f = _mk(name, name, cob_params, path, 1, [])
        for ln, raw in enumerate(lines):
            line = ln + 1
            am = re.match(r"\s*ACCEPT\s+([\w-]+)", raw, re.I)
            if am:
                f["ops"].append({"op": "assign", "line": line, "lhs": [am.group(1)],
                                 "rhs": {"idents": [], "concat": False, "strlit": False,
                                         "calls": [{"callee": "ACCEPT", "recv": "", "recvType": "",
                                                    "full": "ACCEPT", "args": [], "line": line}]}})
            for m in _COB_MOVE.finditer(raw):
                f["ops"].append({"op": "assign", "line": line, "lhs": [m.group(2)],
                                 "rhs": parse_expr(m.group(1), "cobol")})
            for m in _COB_COMPUTE.finditer(raw):
                f["ops"].append({"op": "assign", "line": line, "lhs": [m.group(1)],
                                 "rhs": parse_expr(m.group(2), "cobol")})
            # STRING <ops> [DELIMITED BY ..] INTO <target>: builds a string (taint flow)
            sm = re.search(r"\bSTRING\s+(.+?)\s+INTO\s+([\w-]+)", raw, re.I)
            if sm:
                srcs = re.sub(r"(?i)\bDELIMITED\s+BY\s+(?:SIZE|SPACE|SPACES|\S+)", " ", sm.group(1))
                rhs = parse_expr(srcs, "cobol"); rhs["concat"] = True
                f["ops"].append({"op": "assign", "line": line, "lhs": [sm.group(2)], "rhs": rhs})
            cm = _COB_CALL.search(raw)
            if cm:
                args = [parse_expr(a, "cobol") for a in re.split(r"\s+", (cm.group(2) or "").strip()) if a]
                callee = cm.group(1).strip('"\'')
                f["ops"].append({"op": "expr", "line": line,
                                 "rhs": {"idents": [], "concat": False, "strlit": False,
                                         "calls": [{"callee": callee, "recv": "", "recvType": "",
                                                    "full": callee, "args": args, "line": line}]}})
        for m in _COB_EXECSQL.finditer(body):
            line = body[:m.start()].count("\n") + 1
            sqltext = m.group(1)
            hostvars = re.findall(r":([\w-]+)", sqltext)
            # Static embedded SQL uses :host-vars as BIND PARAMETERS (not injectable).
            # Only DYNAMIC SQL (EXECUTE IMMEDIATE / PREPARE of a built string) is a
            # SQL-injection sink -> distinct callee so the rule flags only that.
            dynamic = re.search(r"\bEXECUTE\s+IMMEDIATE\b|\bPREPARE\b", sqltext, re.I)
            callee = "EXEC_SQL_DYNAMIC" if dynamic else "EXEC_SQL"
            full = "EXEC SQL EXECUTE IMMEDIATE" if dynamic else "EXEC SQL"
            e = {"idents": hostvars, "concat": bool(hostvars), "strlit": True,
                 "calls": [{"callee": callee, "recv": "", "recvType": "", "full": full,
                            "args": [{"idents": hostvars, "concat": False, "strlit": True, "calls": []}],
                            "line": line}]}
            f["ops"].append({"op": "expr", "line": line, "rhs": e})
        funcs.append(f)
    return {"dir": src_dir, "functions": funcs, "call_seen": 0, "call_total": 0}


# ---------------- shared ----------------
def _walkcalls(e, line):
    if not isinstance(e, dict):
        return
    for c in e.get("calls") or []:
        if not c.get("line"):
            c["line"] = line
        for a in c.get("args") or []:
            _walkcalls(a, line)


def _finalize(ir):
    for f in ir.get("functions", []):
        for op in f.get("ops", []):
            ol = op.get("line", 0)
            _walkcalls(op.get("rhs"), ol)
            for v in op.get("values") or []:
                _walkcalls(v, ol)
    return ir


def _mk(pkg, name, params, path, line, ops):
    return {"key": (pkg + "." if pkg else "") + name, "name": name, "recvType": "",
            "params": [{"name": p} for p in params], "paramNames": params,
            "results": [], "pkg": pkg, "pos": f"{os.path.abspath(path)}:{line}:1",
            "anonymous": False, "ops": ops}


def _files(src_dir, exts):
    out = []
    for dp, dns, fns in os.walk(src_dir):
        dns[:] = [d for d in dns if d not in ("vendor", "node_modules", ".git")]
        for fn in fns:
            if os.path.splitext(fn)[1].lower() in exts:
                out.append(os.path.join(dp, fn))
    return out


def _read(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


EXTRACTORS = {"plsql": extract_plsql, "vb6": extract_vb, "cobol": extract_cobol}
LINE_FAMILY = {"plsql": "plsql", "vb6": "dotnet", "cobol": "cobol"}


def extract_ir(lang, src_dir):
    return _finalize(EXTRACTORS[lang](src_dir))
