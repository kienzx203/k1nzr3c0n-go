#!/usr/bin/env python3
"""Semgrep-style AST pattern matcher (tree-sitter based). Patterns are parsed with
the SAME grammar as the target (exactly how semgrep-core works), then matched
tree-vs-tree with metavariables ($X, unified by name), anonymous metavars ($_),
and ellipsis (...). Supports pattern / patterns(AND) / pattern-either(OR) /
pattern-not / pattern-inside / pattern-not-inside / metavariable-pattern /
metavariable-regex / focus-metavariable. Falls back cleanly (no match) on
anything it cannot parse, so it never crashes a scan.
"""
import re

try:
    from tree_sitter_language_pack import get_parser
except Exception:  # noqa: BLE001
    get_parser = None

_PARSERS = {}


def _parser(ts_lang):
    if get_parser is None:
        return None
    if ts_lang not in _PARSERS:
        try:
            _PARSERS[ts_lang] = get_parser(ts_lang)
        except Exception:  # noqa: BLE001
            _PARSERS[ts_lang] = None
    return _PARSERS[ts_lang]


_MV_PREFIX = "CXMVZZ"
_ELL = "CXELLZZ"
_DEEP = "CXDEEPZZ"


def _preprocess(pat):
    """Returns (preprocessed_source, typed_map). `(TYPE $X)` typed metavariables are
    stripped to the metavar and recorded in typed_map {placeholder: type}; $NAME ->
    CXMVZZNAME, $_ -> anon, `<... X ...>` -> CXDEEPZZ(X), ... -> CXELLZZ."""
    anon = [0]
    tc = [0]
    typed = {}

    # CodeQL typed metavariable: `(type $X)` / `(type $_)` -> keep the metavar, record
    # its required type. Guarded: the leading token must be a known type keyword.
    def typed_repl(m):
        tystr, name = m.group(1).strip(), m.group(2)
        first = re.split(r"[\s*]+", tystr)[0]
        if first not in _TYPE_KW:
            return m.group(0)                 # not a typed metavar — leave as-is
        if name == "_":
            tc[0] += 1
            name = "TYPED%d" % tc[0]
        typed[_MV_PREFIX + name] = _norm_type(tystr)
        return " $" + name + " "
    s = re.sub(r"\(\s*([A-Za-z_][\w\s\*]*?)\s+\$([A-Za-z_]\w*|_)\s*\)", typed_repl, pat)

    def repl(m):
        name = m.group(1)
        if name == "_":
            anon[0] += 1
            return _MV_PREFIX + "ANON%d" % anon[0]
        return _MV_PREFIX + name
    s = re.sub(r"\$([A-Za-z_][A-Za-z0-9_]*)", repl, s)
    # deep-expression `<... INNER ...>` -> a marker call CXDEEPZZ( INNER ) BEFORE the
    # plain `...` rewrite (the inner dots are part of the deep-ellipsis syntax).
    s = re.sub(r"<\.\.\.\s*(.*?)\s*\.\.\.>", lambda m: " " + _DEEP + "(" + m.group(1) + ") ", s, flags=re.S)
    s = _sub_ellipsis(s)
    return s, typed


def _sub_ellipsis(s):
    """Replace `...` with the ellipsis placeholder, context-aware: a STATEMENT-level
    `...` (paren/bracket depth 0, after a `;`/`{`/`}`/start) becomes its own statement
    `CXELLZZ ;` so `a(); ... c();` keeps the ellipsis as a middle statement (otherwise
    `CXELLZZ c()` re-parses as a declaration and the ellipsis is lost). Elsewhere
    (inside call args / an expression) it stays a bare `CXELLZZ`."""
    out, depth, i, L = [], 0, 0, len(s)
    while i < L:
        ch = s[i]
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth = max(0, depth - 1)
        if s.startswith("...", i):
            prev = next((c for c in reversed(out) if not c.isspace()), "")
            if depth == 0 and (prev in ";{}:" or prev == ""):   # ; { } or a case/label `:`
                out.append(" " + _ELL + " ; ")     # statement-sequence ellipsis
            else:
                out.append(" " + _ELL + " ")        # arg / expression ellipsis
            i += 3
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _txt(n, src):
    return src[n.start_byte:n.end_byte].decode("utf-8", "replace")


def _is_mv(n, src):
    t = _txt(n, src)
    return t if (n.child_count == 0 and t.startswith(_MV_PREFIX)) else None


_ELL_TRANSPARENT = ("expression_statement", "statement", "ERROR")


def _is_ellipsis(n, src):
    """`...` — a bare marker, or a STATEMENT whose only content is the marker (so
    `...` works both in arg lists and between statements). Recursion is restricted to
    transparent statement wrappers: `sizeof(...)` / `foo(...)` are a sizeof/call that
    CONTAIN the marker, NOT an ellipsis themselves."""
    if n.child_count == 0:
        return _txt(n, src) == _ELL
    if n.type not in _ELL_TRANSPARENT:
        return False
    named = [c for c in n.children if c.is_named]
    return len(named) == 1 and _is_ellipsis(named[0], src)


_DECLARATOR_WRAP = ("pointer_declarator", "array_declarator", "reference_declarator",
                    "parenthesized_declarator", "init_declarator")


def _assign_parts(n):
    """Normalize an assignment / declaration-with-initializer to (name, value),
    so `$X = e` matches both `x = e` and `T x = e` (Semgrep AST normalization)."""
    t = n.type
    if t in ("local_variable_declaration", "field_declaration", "property_declaration"):
        # Java/Kotlin: find the variable_declarator and return its (name, value).
        for c in n.children:
            if c.type in ("variable_declarator",):
                nm = c.child_by_field_name("name")
                val = c.child_by_field_name("value")
                if nm is not None and val is not None:
                    return (nm, val)
        return None
    if t in ("expression_statement", "declaration"):
        named = [c for c in n.children if c.is_named]
        inits = [c for c in named if c.type in ("assignment_expression", "init_declarator")]
        if inits:
            return _assign_parts(inits[0])
        if len(named) == 1:
            return _assign_parts(named[0])
        return None
    if t == "assignment_expression":
        l = n.child_by_field_name("left")
        r = n.child_by_field_name("right")
        return (l, r) if (l and r) else None
    if t == "init_declarator":
        d = n.child_by_field_name("declarator")
        v = n.child_by_field_name("value")
        while d is not None and d.type in _DECLARATOR_WRAP:
            nd = d.child_by_field_name("declarator")
            d = nd or next((c for c in d.children if c.is_named), None)
        return (d, v) if (d and v) else None
    return None


_TOP = {"translation_unit", "program", "source_file", "module", "compilation_unit"}
# boilerplate top-level nodes to ignore when finding the significant pattern node
_SKIP_TOP = {"php_tag", "text", "comment", "line_comment", "block_comment",
             "shebang", "package_clause", "import_declaration"}
_FUNC = {"function_definition", "function_declaration", "method_declaration",
         "function_item", "method_definition"}
_BLOCK = {"compound_statement", "block", "statement_block"}
_EXPRSTMT = {"expression_statement"}


def _significant(node):
    """Descend through harness/wrapper nodes to the meaningful pattern node.
    Returns a block node unchanged when the pattern is a multi-statement sequence."""
    cur = node
    for _ in range(40):
        if cur.type in _TOP:
            named = [c for c in cur.children if c.is_named and c.type not in _SKIP_TOP]
            if len(named) == 1:
                cur = named[0]; continue
            return cur
        if cur.type in _FUNC:
            body = cur.child_by_field_name("body") or next(
                (c for c in cur.children if c.type in _BLOCK), None)
            if body is not None:
                cur = body; continue
            return cur
        if cur.type in _BLOCK | _EXPRSTMT:
            named = [c for c in cur.children if c.is_named]
            if len(named) == 1:
                cur = named[0]; continue
            return cur          # 0 or >1 statements → keep (sequence pattern)
        return cur
    return cur


class Pattern:
    def __init__(self, root, src, ts_lang, typed=None):
        self.root = root
        self.src = src
        self.ts_lang = ts_lang
        self.typed = typed or {}      # {placeholder: required C type} for typed metavars


# ---- type inference (CodeQL-style typed metavariables `(type $X)`) -----------
_TYPE_KW = {"void", "char", "short", "int", "long", "float", "double", "signed",
            "unsigned", "bool", "_Bool", "wchar_t", "size_t", "ssize_t", "ptrdiff_t",
            "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t",
            "uint32_t", "uint64_t", "intptr_t", "uintptr_t", "off_t", "time_t"}
_TYPE_DROP = {"const", "volatile", "register", "static", "struct", "union", "enum",
              "extern", "inline", "restrict", "_Atomic"}


def _norm_type(s):
    """Canonicalize a C/C++ type string so `(unsigned short int)` == `(unsigned short)`
    and `char*` == `char *`."""
    s = re.sub(r"//.*|/\*.*?\*/", " ", s)
    s = s.replace("*", " * ")
    toks = [t for t in s.split() if t not in _TYPE_DROP]
    stars = sum(1 for t in toks if t == "*")
    words = [t for t in toks if t != "*"]
    if "int" in words and len(words) > 1 and any(
            w in ("short", "long", "unsigned", "signed") for w in words):
        words = [w for w in words if w != "int"]      # drop redundant 'int'
    if words == ["unsigned"]:
        words = ["unsigned", "int"]
    if words == ["signed"]:
        words = ["signed", "int"]
    base = " ".join(words)
    return (base + " " + "*" * stars).strip() if stars else base


_INT_RANK = {"bool": 0, "char": 1, "short": 2, "int": 3, "long": 4, "size_t": 4,
             "float": 5, "double": 6}


class TypeCtx:
    __slots__ = ("var", "func_ret")

    def __init__(self):
        self.var = {}        # variable name -> normalized type
        self.func_ret = {}   # function name -> normalized return type


def _decl_name_stars(node, src, stars=0):
    """From a declarator subtree return (identifier_name, pointer_depth)."""
    t = node.type
    if t in ("identifier", "field_identifier", "type_identifier"):
        return _txt(node, src), stars
    if t == "pointer_declarator":
        d = node.child_by_field_name("declarator")
        return _decl_name_stars(d, src, stars + 1) if d else (None, stars)
    if t in ("init_declarator", "array_declarator", "parenthesized_declarator",
             "reference_declarator", "function_declarator"):
        d = node.child_by_field_name("declarator")
        return _decl_name_stars(d, src, stars) if d else (None, stars)
    for c in node.children:
        if c.is_named:
            r = _decl_name_stars(c, src, stars)
            if r[0]:
                return r
    return None, stars


def build_type_ctx(troot, src):
    ctx = TypeCtx()
    for n in _walk(troot):
        t = n.type
        # NB: field_declaration deliberately EXCLUDED — struct/class member names must
        # not pollute the flat variable namespace (would clobber same-named locals/params).
        if t in ("declaration", "parameter_declaration"):
            ty = n.child_by_field_name("type")
            if ty is None:
                continue
            base = _txt(ty, src)
            for d in n.children:
                if not d.is_named or d is ty:
                    continue
                name, stars = _decl_name_stars(d, src)
                if name:
                    ctx.var[name] = _norm_type(base + " *" * stars)
        elif t in ("function_definition", "function_declarator"):
            ty = n.child_by_field_name("type")
            decl = n.child_by_field_name("declarator")
            if ty is not None and decl is not None:
                name, stars = _decl_name_stars(decl, src)
                if name:
                    ctx.func_ret.setdefault(name, _norm_type(_txt(ty, src) + " *" * stars))
    return ctx


def infer_type(node, src, ctx):
    """Best-effort C/C++ type of an expression node (normalized), or None."""
    if node is None or ctx is None:
        return None
    t = node.type
    if t in ("identifier", "field_identifier"):
        return ctx.var.get(_txt(node, src))
    if t == "number_literal":
        s = _txt(node, src).lower()
        if s.startswith("0x") or s.startswith("0b"):
            base = "long" if "l" in s.replace("0x", "").replace("0b", "") else "int"
            return "unsigned " + base if "u" in s else base
        if "." in s or "e" in s or s.endswith("f"):
            return "float" if s.endswith("f") else "double"
        base = "long" if "l" in s else "int"
        return "unsigned " + base if "u" in s else base   # 2u / 10UL → unsigned
    if t == "char_literal":
        return "char"
    if t in ("string_literal", "concatenated_string", "raw_string_literal"):
        return "char *"
    if t == "cast_expression":
        ty = node.child_by_field_name("type")
        if ty is not None:
            base = _norm_type(_txt(ty, src))
            dcl = node.child_by_field_name("declarator") or node.child_by_field_name("value")
            return base
    if t in ("parenthesized_expression",):
        k = [c for c in node.children if c.is_named]
        return infer_type(k[0], src, ctx) if k else None
    if t == "pointer_expression":
        toks = [ch for ch in node.children]
        op = next((_txt(c, src) for c in toks if not c.is_named and _txt(c, src) in ("&", "*")), None)
        arg = next((c for c in toks if c.is_named), None)
        at = infer_type(arg, src, ctx)
        if op == "&" and at:
            return _norm_type(at + " *")
        if op == "*" and at and at.endswith("*"):
            return _norm_type(at[:-1])
        return None
    if t == "call_expression":
        fn = next((c for c in node.children if c.is_named), None)
        if fn is not None and fn.type in _NAME_TYPES:
            return ctx.func_ret.get(_txt(fn, src))
        return None
    if t in ("subscript_expression",):
        arr = node.child_by_field_name("argument") or next((c for c in node.children if c.is_named), None)
        at = infer_type(arr, src, ctx)
        if at and at.endswith("*"):
            return _norm_type(at[:-1])
        return None
    if t in ("binary_expression",):
        l = infer_type(node.child_by_field_name("left"), src, ctx)
        r = infer_type(node.child_by_field_name("right"), src, ctx)
        return _promote(l, r)
    if t in ("assignment_expression", "init_declarator"):
        return infer_type(node.child_by_field_name("left") or node.child_by_field_name("declarator"), src, ctx)
    return None


def _promote(a, b):
    if a and a.endswith("*"):
        return a
    if b and b.endswith("*"):
        return b
    if a and b:
        ra, rb = _INT_RANK.get(a.split()[-1], 3), _INT_RANK.get(b.split()[-1], 3)
        if ra != rb:
            return a if ra > rb else b
        # C usual arithmetic conversions: at equal rank, unsigned wins (order-independent)
        if "unsigned" in a:
            return a
        if "unsigned" in b:
            return b
        return a
    return a or b


def _type_match(inferred, required):
    if inferred is None:
        return False
    return _norm_type(inferred) == _norm_type(required)


_CUR_TCTX = None       # target type context for the file currently being matched
_CUR_TYPED = None      # {placeholder: required_type} of the pattern currently matching


def _harnesses(pre, ts_lang):
    """Language-appropriate wrappers (Semgrep's multiple start-rules). Trying only
    valid ones avoids, e.g., a PHP snippet parsing clean as inert HTML text."""
    if ts_lang == "php":
        return ["<?php " + pre + ";", "<?php " + pre,
                "<?php function CXFN(){\n" + pre + ";\n}",
                "<?php class CXC { function CXFN(){\n" + pre + ";\n} }"]
    if ts_lang == "python":
        return [pre, pre + "\n", "def CXFN():\n " + pre.replace("\n", "\n ") + "\n"]
    if ts_lang == "ruby":
        return [pre, pre + "\n", "def cxfn\n" + pre + "\nend"]
    if ts_lang in ("go", "rust"):
        return [pre, pre + ";", "func CXFN(){\n" + pre + "\n}",
                "fn CXFN(){\n" + pre + ";\n}"]
    # c / c++ / java / c# / javascript / typescript / kotlin / scala / swift ...
    return [pre, pre + ";", "void CXFN(){\n" + pre + "\n}",
            "void CXFN(){\n" + pre + ";\n}", "class CXC { void CXFN(){\n" + pre + "\n} }"]


_COMPILE_CACHE = {}


def compile_pattern(pattern_str, ts_lang):
    key = (ts_lang, pattern_str)
    if key in _COMPILE_CACHE:
        return _COMPILE_CACHE[key]
    r = _compile_pattern(pattern_str, ts_lang)
    _COMPILE_CACHE[key] = r
    return r


def _compile_pattern(pattern_str, ts_lang):
    p = _parser(ts_lang)
    if p is None or not isinstance(pattern_str, str):
        return None
    pre, typed = _preprocess(pattern_str)
    for h in _harnesses(pre, ts_lang):
        try:
            tree = p.parse(h.encode())
        except Exception:  # noqa: BLE001
            continue
        if _count_errors(tree.root_node) > 0:
            continue
        sig = _significant(tree.root_node)
        if sig is not None and sig.type not in _TOP:
            return Pattern(sig, h.encode(), ts_lang, typed=typed)
    return None


def _count_errors(n):
    c = 1 if n.type == "ERROR" or n.is_missing else 0
    for ch in n.children:
        c += _count_errors(ch)
    return c


# ---- the core tree matcher (generator: yields every satisfying binding set) --
_NORM_TYPES = ("assignment_expression", "expression_statement", "declaration",
               "init_declarator",
               # Java/Kotlin: a `T x = v` local and a `T x = v` class FIELD are the same
               # construct for matching — so a `String $NAME = $VAL;` pattern matches a
               # field_declaration too (hardcoded-secret in a field, not just a local).
               "local_variable_declaration", "field_declaration",
               "property_declaration")


def _match(pn, psrc, tn, tsrc, env):
    """Bool wrapper: does pn match tn under some binding extending env?"""
    for _ in _match_all(pn, psrc, tn, tsrc, env):
        return True
    return False


def _match_all(pn, psrc, tn, tsrc, env):
    """Yield each binding set (dict) under which pattern node pn matches target tn.
    Multiple yields = multiple valid metavariable bindings (Semgrep's model), so a
    later constraint (pattern-inside / metavariable correlation) can pick a consistent one."""
    mv = _is_mv(pn, psrc)
    if mv is not None:
        # a metavariable binds to a MEANINGFUL (named) node, never to a punctuation /
        # operator token (e.g. `<... $X ...>` must not bind $X to `+`/`*`).
        if not tn.is_named:
            return
        if _CUR_TYPED and mv in _CUR_TYPED:   # CodeQL typed metavariable `(type $X)`
            if not _type_match(infer_type(tn, tsrc, _CUR_TCTX), _CUR_TYPED[mv]):
                return
        if mv.startswith(_MV_PREFIX + "ANON"):
            yield env; return                 # $_ matches anything (named), no binding
        val = _txt(tn, tsrc)
        if mv in env:
            if env[mv] == val:
                yield env
            return
        e = dict(env); e[mv] = val
        yield e; return
    # deep-expression `<... INNER ...>`: INNER matches tn or any descendant.
    inner = _deep_inner(pn, psrc)
    if inner is not None:
        seen = set()
        for desc in _walk(tn):
            for e in _match_all(inner, psrc, desc, tsrc, env):
                k = tuple(sorted(e.items()))
                if k not in seen:
                    seen.add(k); yield e
        return
    # string-ellipsis: a string literal written "..." matches any string literal.
    if _is_str(pn) and _ELL in _txt(pn, psrc):
        if _is_str(tn):
            yield env
        return
    if pn.type != tn.type:
        # decl/assign normalization: `$X = e` (assignment) matches `T x = e` (decl)
        if pn.type in _NORM_TYPES and tn.type in _NORM_TYPES:
            pa, ta = _assign_parts(pn), _assign_parts(tn)
            if pa and ta:
                for e1 in _match_all(pa[0], psrc, ta[0], tsrc, env):
                    yield from _match_all(pa[1], psrc, ta[1], tsrc, e1)
        return
    # commas are pure separators — drop on both sides so `f("...", ...)` lines up.
    pc = [c for c in pn.children if c.type != ","]
    tc = [c for c in tn.children if c.type != ","]
    if not pc and not tc:
        if _txt(pn, psrc) == _txt(tn, tsrc):  # leaf: identifiers/keywords/punct
            yield env
        return
    yield from _match_seq_all(pc, psrc, tc, tsrc, env)


def _match_seq_all(pc, psrc, tc, tsrc, env):
    """Yield bindings matching a pattern child sequence vs target children, `...`
    ellipsis matching any run (all split points explored)."""
    if not pc:
        if not tc:
            yield env
        return
    head = pc[0]
    if _is_ellipsis(head, psrc):
        rest = pc[1:]
        if not rest:
            yield env; return                 # trailing ellipsis eats the remainder
        for i in range(len(tc) + 1):
            yield from _match_seq_all(rest, psrc, tc[i:], tsrc, env)
        return
    if not tc:
        return
    for e1 in _match_all(head, psrc, tc[0], tsrc, env):
        yield from _match_seq_all(pc[1:], psrc, tc[1:], tsrc, e1)


def _deep_inner(pn, psrc):
    """If pn is the deep-expression marker call CXDEEPZZ(INNER), return INNER."""
    if "call" not in pn.type:
        return None
    named = [c for c in pn.children if c.is_named]
    if not named or named[0].type not in ("identifier", "field_identifier"):
        return None
    if _txt(named[0], psrc) != _DEEP:
        return None
    args = next((c for c in pn.children if "argument" in c.type), None)
    inner = [c for c in (args.children if args else []) if c.is_named]
    return inner[0] if inner else None


def _is_str(n):
    t = n.type
    return ("string" in t) or t in ("char_literal", "raw_string_literal",
                                     "interpreted_string_literal", "concatenated_string")


def _walk(node):
    yield node
    for ch in node.children:
        yield from _walk(ch)


# types that decl/assign normalization bridges — an assign-shaped pattern must also
# scan declarations/init-declarators (and vice-versa), or the type index hides them.
_NORM_FAMILY = ("assignment_expression", "expression_statement", "declaration",
                "init_declarator", "local_variable_declaration", "field_declaration",
                "property_declaration")


def _candidates(pat, troot, nodes, by_type):
    """Restrict the match scan to nodes of the pattern-root's type (big speedup),
    unless the root is a wildcard (metavar / string-ellipsis) that can match any type."""
    root = pat.root
    if by_type is not None and root.child_count and not (_is_str(root) and _ELL in _txt(root, pat.src)):
        if _is_mv(root, pat.src) is None and _deep_inner(root, pat.src) is None:
            if root.type in _NORM_FAMILY:
                return [n for t in _NORM_FAMILY for n in by_type.get(t, ())]
            return by_type.get(root.type, ())
    return nodes if nodes is not None else list(_walk(troot))


def find_matches(pat, troot, tsrc, nodes=None, by_type=None):
    """Yield (node, env) for every target node × binding matching the pattern.
    `nodes`/`by_type` are built once per file (single-walk + type index)."""
    global _CUR_TYPED
    _CUR_TYPED = getattr(pat, "typed", None) or None
    # A multi-statement (block) positive pattern — e.g. `$F1($P); ... $F2($P)` — must
    # match as a SUB-SEQUENCE starting at ANY statement in any block, not block-start-
    # anchored (otherwise a leading declaration before the first stmt breaks the match).
    if pat.root.type in _BLOCK:
        pstmts = [c for c in pat.root.children if c.is_named]
        if by_type is not None:
            blocks = [b for bt in _BLOCK for b in by_type.get(bt, ())]
        else:
            blocks = [n for n in (nodes if nodes is not None else _walk(troot)) if n.type in _BLOCK]
        for comp in blocks:
            tstmts = [c for c in comp.children if c.is_named]
            for i in range(len(tstmts)):
                for _end, env in _match_stmts(pstmts, pat.src, tstmts[i:], tsrc, {}, None):
                    yield tstmts[i], env
        _CUR_TYPED = None
        return
    for tn in _candidates(pat, troot, nodes, by_type):
        for env in _match_all(pat.root, pat.src, tn, tsrc, {}):
            yield tn, env
    _CUR_TYPED = None


# ---- rule-level evaluation (operators) -------------------------------------
def _collect_ops(node, ops):
    """Flatten a rule's pattern tree into operator lists."""
    if isinstance(node, dict):
        for k in ("pattern",):
            if isinstance(node.get(k), str):
                ops["pos"].append(node[k])
        if isinstance(node.get("pattern-not"), str):
            ops["not"].append(node["pattern-not"])
        if isinstance(node.get("pattern-inside"), str):
            ops["inside"].append(node["pattern-inside"])
        if isinstance(node.get("pattern-not-inside"), str):
            ops["not_inside"].append(node["pattern-not-inside"])
        if isinstance(node.get("focus-metavariable"), str):
            ops["focus"].append(node["focus-metavariable"])
        mvp = node.get("metavariable-pattern")
        if isinstance(mvp, dict) and mvp.get("metavariable"):
            sub = {"pos": [], "not": [], "inside": [], "not_inside": [],
                   "focus": [], "mvp": [], "mvr": [], "mvc": []}
            _collect_ops(mvp, sub)
            ops["mvp"].append((mvp["metavariable"], sub))
        mvr = node.get("metavariable-regex")
        if isinstance(mvr, dict) and mvr.get("metavariable") and mvr.get("regex"):
            ops["mvr"].append((mvr["metavariable"], mvr["regex"]))
        mvc = node.get("metavariable-comparison")
        if isinstance(mvc, dict) and mvc.get("comparison"):
            ops.setdefault("mvc", []).append(mvc)
        # pattern-either is an OR of positives; patterns is an AND — for the common
        # rule shape (one positive group + filters) both are traversed the same way.
        for key in ("patterns", "pattern-either"):
            for sub in node.get(key) or []:
                _collect_ops(sub, ops)
    elif isinstance(node, str):
        ops["pos"].append(node)


def _byte_range(n):
    return (n.start_byte, n.end_byte)


def _match_stmts(pstmts, psrc, tstmts, tsrc, env, last_end):
    """Yield (end_byte, binding) for each way the pattern statement-sequence matches
    a prefix of target statements (statement-level `...` = any run of statements)."""
    if not pstmts:
        yield last_end, env
        return
    head = pstmts[0]
    if _is_ellipsis(head, psrc):
        rest = pstmts[1:]
        if not rest:
            yield (tstmts[-1].end_byte if tstmts else last_end), env
            return
        for i in range(len(tstmts) + 1):
            yield from _match_stmts(rest, psrc, tstmts[i:], tsrc, env, last_end)
        return
    if not tstmts:
        return
    for e1 in _match_all(head, psrc, tstmts[0], tsrc, env):
        yield from _match_stmts(pstmts[1:], psrc, tstmts[1:], tsrc, e1, tstmts[0].end_byte)


def _regions(pat, troot, tsrc, nodes=None, by_type=None):
    """Byte ranges a (not-)inside pattern covers. A multi-statement pattern is
    matched as a sub-sequence starting at any statement in any block (faithful
    pattern-inside); a single node pattern uses its matched node's range."""
    global _CUR_TYPED
    _CUR_TYPED = getattr(pat, "typed", None) or None
    block = pat.root
    if block.type in _BLOCK:
        pstmts = [c for c in block.children if c.is_named]
        if by_type is not None:
            comps = [c for bt in _BLOCK for c in by_type.get(bt, ())]
        else:
            comps = [c for c in (nodes if nodes is not None else _walk(troot)) if c.type in _BLOCK]
        out = []
        for comp in comps:
            tstmts = [c for c in comp.children if c.is_named]
            for i in range(len(tstmts)):
                for end, env in _match_stmts(pstmts, pat.src, tstmts[i:], tsrc, {}, None):
                    if end is not None:
                        out.append((tstmts[i].start_byte, end, dict(env)))
        return out
    return [(n.start_byte, n.end_byte, env) for n, env in find_matches(pat, troot, tsrc, nodes, by_type)]


def _consistent(e1, e2):
    """Two binding sets agree where they share a (non-anonymous) metavariable."""
    for k, v in e1.items():
        if k in e2 and e2[k] != v:
            return False
    return True


def _contains(outer, inner):
    return outer.start_byte <= inner.start_byte and inner.end_byte <= outer.end_byte


_POS_KEYS = ("pattern", "patterns", "pattern-either")
_FILTER_KEYS = ("pattern-not", "pattern-inside", "pattern-not-inside",
                "metavariable-pattern", "metavariable-regex", "metavariable-comparison",
                "focus-metavariable")


def _is_pos(item):
    return isinstance(item, str) or (isinstance(item, dict) and any(k in item for k in _POS_KEYS))


def _is_producer(item):
    """A positive that PRODUCES candidate nodes. A `pattern-either` of only filters
    (e.g. OR of pattern-inside) produces nothing — it is a filter, not a producer."""
    if isinstance(item, str):
        return True
    if not isinstance(item, dict):
        return False
    if "pattern" in item:
        return True
    # a `patterns`/`pattern-either` group produces only if a CHILD produces; a group of
    # only filters (pattern-inside/not-inside) is itself a filter, not a producer.
    if "patterns" in item:
        return any(_is_producer(b) for b in (item.get("patterns") or []))
    if "pattern-either" in item:
        return any(_is_producer(b) for b in (item.get("pattern-either") or []))
    return False


def _overlap(r1, r2):
    return not (r1[1] <= r2[0] or r2[1] <= r1[0])


def _and(a, b):
    """AND two result sets: keep pairs whose bindings are consistent and ranges
    overlap, merging their metavariable bindings."""
    out = []
    for n1, e1 in a:
        r1 = _byte_range(n1)
        for n2, e2 in b:
            if _consistent(e1, e2) and _overlap(r1, _byte_range(n2)):
                m = dict(e1); m.update(e2)
                out.append((n1, m))
                break
    return out


def _has_key(node, key):
    if isinstance(node, dict):
        if key in node:
            return True
        return any(_has_key(v, key) for v in node.values())
    if isinstance(node, list):
        return any(_has_key(v, key) for v in node)
    return False


def match_rule(rule, ts_lang, troot, tsrc, nodes=None):
    """Evaluate a Semgrep rule over a parsed tree → list of (node, env). Boolean tree
    evaluated COMPOSITIONALLY (pattern-either=OR, patterns=AND, each branch keeps its
    own filters). A non-compiling pattern yields [] for its branch only (never a wrong
    match). `nodes` is a node list materialised once per file."""
    if nodes is None:
        nodes = list(_walk(troot))
    # metavariable-analysis (entropy / redos — Semgrep Pro) can't be evaluated here;
    # a rule using it would otherwise fire on EVERYTHING → skip it entirely (no FP).
    if _has_key(rule, "metavariable-analysis"):
        return []
    by_type = {}
    for n in nodes:
        by_type.setdefault(n.type, []).append(n)
    ctx = (ts_lang, troot, tsrc, nodes, by_type)
    out, seen = [], set()
    for node, env in _eval(rule, ctx):
        k = _byte_range(node)
        if k not in seen:
            seen.add(k)
            out.append((node, env))
    return out


def _eval(node, ctx):
    """Recursively evaluate a pattern tree node → list of (node, env)."""
    ts_lang, troot, tsrc, nodes, by_type = ctx
    if isinstance(node, str):
        node = {"pattern": node}
    if not isinstance(node, dict):
        return []
    results = None
    if "pattern-either" in node:                 # OR
        acc = []
        for sub in (node.get("pattern-either") or []):   # None-safe (empty key → [])
            acc += _eval(sub, ctx)
        results = acc
    if "patterns" in node:                        # AND of producers + its own filters
        items = node.get("patterns") or []        # None-safe
        cand = None
        for it in items:
            if _is_producer(it):
                r = _eval(it, ctx)
                cand = r if cand is None else _and(cand, r)
        cand = _apply_filter_items(cand or [], items, ctx)
        results = cand if results is None else _and(results, cand)
    if "pattern" in node:                         # a single positive pattern
        cp = compile_pattern(node["pattern"], ts_lang)
        r = list(find_matches(cp, troot, tsrc, nodes, by_type)) if cp else []
        results = r if results is None else _and(results, r)
    if results is None:
        results = []
    sib = [{k: node[k]} for k in _FILTER_KEYS if k in node]   # filters at THIS dict level
    if sib:
        results = _apply_filter_items(results, sib, ctx)
    return results


def _apply_filter_items(cands, items, ctx):
    """Apply pattern-not / pattern-(not-)inside / metavariable-* filters (from a list
    of operator items) to candidate (node, env) pairs, with metavariable correlation."""
    if not cands:
        return []
    ts_lang, troot, tsrc, nodes, by_type = ctx
    # a pattern-either made only of FILTERS = OR of those filters: a candidate passes
    # if it satisfies at least one branch (e.g. "free($P) inside array[] OR inside &$P").
    for it in items:
        if not isinstance(it, dict) or _is_producer(it):
            continue
        if "pattern-either" in it:          # OR of filter branches
            branches = it.get("pattern-either") or []
            cands = [c for c in cands if any(_apply_filter_items([c], [b], ctx) for b in branches)]
            if not cands:
                return []
        elif "patterns" in it:              # AND of nested filter sub-items
            cands = _apply_filter_items(cands, it.get("patterns") or [], ctx)
            if not cands:
                return []
    nots, insides, notins, mvp, mvr, mvc = [], [], [], [], [], []
    for it in items:
        if not isinstance(it, dict):
            continue
        if isinstance(it.get("pattern-not"), str):
            cp = compile_pattern(it["pattern-not"], ts_lang)
            if cp:
                nots.append(cp)
            else:
                return []        # fail-safe: an unevaluable exclusion → suppress (no FP)
        if isinstance(it.get("pattern-inside"), str):
            cp = compile_pattern(it["pattern-inside"], ts_lang)
            if cp:
                insides.append(cp)
        if isinstance(it.get("pattern-not-inside"), str):
            cp = compile_pattern(it["pattern-not-inside"], ts_lang)
            if cp:
                notins.append(cp)
            else:
                return []        # fail-safe: an unevaluable exclusion → suppress (no FP)
        m = it.get("metavariable-pattern")
        if isinstance(m, dict) and m.get("metavariable"):
            sub = {"pos": [], "not": [], "inside": [], "not_inside": [], "focus": [],
                   "mvp": [], "mvr": [], "mvc": []}
            _collect_ops(m, sub)
            mvp.append((m["metavariable"],
                        {"pos": [c for c in (compile_pattern(p, ts_lang) for p in sub["pos"]) if c],
                         "not": [c for c in (compile_pattern(p, ts_lang) for p in sub["not"]) if c]}))
        mr = it.get("metavariable-regex")
        if isinstance(mr, dict) and mr.get("metavariable") and mr.get("regex"):
            mvr.append((mr["metavariable"], mr["regex"]))
        mc = it.get("metavariable-comparison")
        if isinstance(mc, dict) and mc.get("comparison"):
            mvc.append(mc)
    inside_ranges = [_regions(ic, troot, tsrc, nodes, by_type) for ic in insides]
    notin_ranges = [_regions(ic, troot, tsrc, nodes, by_type) for ic in notins]
    not_ranges = [_byte_range(n) for nc in nots for n, _ in find_matches(nc, troot, tsrc, nodes, by_type)]
    out = []
    for node, env in cands:
        br = _byte_range(node)
        if any(nr == br or (nr[0] <= br[0] and br[1] <= nr[1]) for nr in not_ranges):
            continue
        if insides and not all(
                any(r[0] <= br[0] and br[1] <= r[1] and _consistent(env, r[2]) for r in regs)
                for regs in inside_ranges):
            continue
        if any(r[0] <= br[0] and br[1] <= r[1] and _consistent(env, r[2])
               for regs in notin_ranges for r in regs):
            continue
        if not _mv_check(env, mvp, mvr, mvc, ts_lang, tsrc):
            continue
        out.append((node, env))
    return out


import ast as _ast

_SAFE_NODES = (_ast.Expression, _ast.Compare, _ast.BoolOp, _ast.BinOp, _ast.UnaryOp,
               _ast.And, _ast.Or, _ast.Not, _ast.Add, _ast.Sub, _ast.Mult, _ast.Div,
               _ast.Mod, _ast.FloorDiv, _ast.Pow, _ast.LShift, _ast.RShift, _ast.BitOr,
               _ast.BitAnd, _ast.BitXor, _ast.Invert, _ast.USub, _ast.UAdd,
               _ast.Lt, _ast.LtE, _ast.Gt, _ast.GtE, _ast.Eq, _ast.NotEq,
               _ast.Constant, _ast.Num, _ast.Load)


def _num(s):
    s = s.strip()
    try:
        return int(s, 0)            # try raw first so hex 0xff isn't stripped
    except ValueError:
        pass
    s2 = s.rstrip("uUlL")
    try:
        return int(s2, 0)
    except ValueError:
        try:
            return float(s.rstrip("fF"))
        except ValueError:
            return None


def _eval_comparison(comp, env, strip=False, base=None):
    """Evaluate a Semgrep metavariable-comparison. Only TRUE when every referenced
    metavariable is a numeric constant and the comparison holds (conservative)."""
    expr = comp
    for name in set(re.findall(r"\$([A-Za-z_]\w*)", comp)):
        val = env.get(_MV_PREFIX + name)
        if val is None:
            return False
        if strip:
            val = val.strip("\"'")
        n = _num(val)
        if n is None:
            return False                  # non-constant → not provably true → no match
        expr = re.sub(r"\$" + re.escape(name) + r"(?!\w)", repr(n), expr)
    expr = expr.replace("&&", " and ").replace("||", " or ").replace("!", " not ")
    try:
        tree = _ast.parse(expr, mode="eval")
    except SyntaxError:
        return False
    for node in _ast.walk(tree):
        if not isinstance(node, _SAFE_NODES):
            return False                  # anything unexpected → refuse (safe)
    try:
        return bool(eval(compile(tree, "<cmp>", "eval"), {"__builtins__": {}}, {}))  # noqa: S307
    except Exception:  # noqa: BLE001
        return False


def _mv_check(env, mvp, mvr, mvc, ts_lang, tsrc):
    for c in mvc or []:
        if not _eval_comparison(c.get("comparison", ""), env,
                                strip=bool(c.get("strip")), base=c.get("base")):
            return False
    for var, regexes in mvr:
        key = _MV_PREFIX + var.lstrip("$")
        val = env.get(key)
        if val is not None and not re.match(regexes, val):  # Semgrep anchors at start
            return False
    for var, sub in mvp:
        key = _MV_PREFIX + var.lstrip("$")
        val = env.get(key)
        if val is None:
            continue
        if any(_val_matches(np, val, ts_lang) for np in sub["not"]):
            return False                  # excluded by metavariable-pattern pattern-not
        if sub["pos"] and not any(_val_matches(pp, val, ts_lang) for pp in sub["pos"]):
            return False                  # not in the allowed set
    return True


def _val_matches(sp, val, ts_lang):
    """Does sub-pattern sp match the bound metavariable text val?"""
    if _txt(sp.root, sp.src) == val:
        return True
    try:
        t = _parser(ts_lang).parse(val.encode())
        return any(True for _ in find_matches(sp, t.root_node, val.encode()))
    except Exception:  # noqa: BLE001
        return False


def _focus_node(node, env, ops, tsrc):
    return None   # focus is cosmetic; reporting the match node is fine


def callee_of(pattern_str, ts_lang):
    """Extract the called function / method NAME from a call-shaped pattern, so a
    Semgrep taint-mode pattern-source/sink/sanitizer can feed the (deeper) callee-
    based taint engine. Returns None for a non-call pattern (can't be reduced)."""
    cp = compile_pattern(pattern_str, ts_lang)
    if cp is None:
        return None
    call = cp.root
    if not _is_callish(call.type):
        call = next((d for d in _walk(cp.root) if _is_callish(d.type)), None)
        if call is None:
            return None

    def nm(t):
        return None if (t.startswith(_MV_PREFIX) or t == _DEEP) else t
    # method-name field directly (Java method_invocation, PHP member_call_expression)
    name_node = call.child_by_field_name("name")
    if name_node is not None and name_node.type in _NAME_TYPES:
        return nm(_txt(name_node, cp.src))
    fn = call.child_by_field_name("function") or next(
        (c for c in call.children if c.is_named and "argument" not in c.type), None)
    if fn is None:
        return None
    if fn.type in _NAME_TYPES:
        return nm(_txt(fn, cp.src))
    # member/field access (obj.method / obj->method / os.system / C# member_access):
    # the METHOD is the LAST name component; obj.$X(...) cannot be reduced.
    names = [d for d in _walk(fn) if d.type in _NAME_TYPES]
    if not names:
        return None
    return nm(_txt(names[-1], cp.src))


def _is_callish(t):
    return "call" in t or "invocation" in t


# identifier-like node types across grammars (C, PHP, JS, Python, Kotlin, Swift…)
_NAME_TYPES = ("identifier", "field_identifier", "name", "simple_identifier",
               "property_identifier", "scoped_identifier", "qualified_identifier")
