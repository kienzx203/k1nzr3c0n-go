"""Kotlin plugin for the tree-sitter extractor.

Maps the tree-sitter-kotlin grammar's node types to the roles the generic
driver (extract.py) expects. This grammar does NOT expose field names
(child_by_field_name returns None), so every accessor below works positionally
over the node's children.

Grammar shapes used here (verified by introspection):
  function_declaration : `fun` simple_identifier function_value_parameters
                         function_body
  anonymous_function   : `fun` function_value_parameters function_body   (no name)
  lambda_literal       : `{` [lambda_parameters `->`] statements `}`
  class/object_declaration : `class`/`object` type_identifier class_body
  property_declaration : binding_pattern_kind variable_declaration `=` <expr>
  assignment           : directly_assignable_expression `=` <expr>
  call_expression      : (navigation_expression | simple_identifier) call_suffix
  navigation_expression: <receiver> navigation_suffix(`.` simple_identifier)
  call_suffix          : value_arguments( `(` value_argument* `)` )
  string_literal       : string_content
                         [interpolation_*_start interpolated_(expression|identifier)]
  additive_expression  : <expr> `+` <expr>
"""

TS_LANG = "kotlin"
EXTS = [".kt", ".kts"]

FUNC_TYPES = {"function_declaration", "secondary_constructor"}
LAMBDA_TYPES = {"lambda_literal", "anonymous_function"}
CLASS_TYPES = {"class_declaration", "object_declaration"}
CALL_TYPES = {"call_expression"}
# `val x = e` / `var x = e` are property_declaration; `x = e` is assignment.
ASSIGN_TYPES = {"property_declaration", "assignment"}
RETURN_TYPES = {"jump_expression"}            # return / throw / break / continue
STRING_TYPES = {"string_literal"}
# string interpolation parts -> treat the enclosing string as concat/taint.
# interpolated_identifier ("$a") is also an IDENT so its captured name flows.
INTERP_TYPES = {"interpolated_expression", "interpolated_identifier"}
BINARY_TYPES = {"additive_expression"}
IDENT_TYPES = {"simple_identifier", "interpolated_identifier"}

_ASSIGN_OPS = {"=", "+=", "-=", "*=", "/=", "%="}


def _t(n, src):
    return src[n.start_byte:n.end_byte].decode("utf-8", "replace")


def pkg_name(root, src, path):
    import os
    return os.path.splitext(os.path.basename(path))[0]


def is_concat(node, src):
    # additive_expression with a '+' operator == string concatenation
    for ch in node.children:
        if ch.type == "+" or _t(ch, src) == "+":
            return True
    return False


def func_name(node, src):
    # first simple_identifier child (function_declaration); anonymous_function
    # / lambda_literal have no name.
    for ch in node.children:
        if ch.type == "simple_identifier":
            return _t(ch, src)
    return ""


def _var_decl_names(n, src, out):
    """Collect the bound name(s) from a (multi_)variable_declaration."""
    if n.type == "variable_declaration":
        for g in n.children:
            if g.type == "simple_identifier":
                out.append(_t(g, src))
                return
    elif n.type == "multi_variable_declaration":
        for g in n.named_children:
            _var_decl_names(g, src, out)


def func_params(node, src):
    names = []
    for ch in node.children:
        if ch.type == "function_value_parameters":
            for p in ch.named_children:
                if p.type == "parameter":
                    for g in p.children:
                        if g.type == "simple_identifier":
                            names.append(_t(g, src))
                            break
        elif ch.type == "lambda_parameters":
            for p in ch.named_children:
                if p.type == "variable_declaration":
                    _var_decl_names(p, src, names)
                elif p.type == "simple_identifier":
                    names.append(_t(p, src))
    return names


def func_body(node):
    # function_declaration / anonymous_function wrap a `function_body`;
    # lambda_literal exposes its `statements` directly. Never return the
    # lambda node itself (the driver would recurse on it endlessly).
    for ch in node.children:
        if ch.type == "function_body":
            return ch
    for ch in node.children:
        if ch.type == "statements":
            return ch
    return None


def class_name(node, src):
    for ch in node.children:
        if ch.type == "type_identifier":
            return _t(ch, src)
    return ""


def _nav_callee_recv(nav, src):
    """From a navigation_expression return (callee, recv_full_text).

    recv is the FULL receiver text so sink/source regexes match the whole
    chain (stmt.executeQuery, Runtime.getRuntime().exec, ...).
    """
    recv_node = None
    sel = None
    for ch in nav.children:
        if ch.type == "navigation_suffix":
            for g in ch.children:
                if g.type == "simple_identifier":
                    sel = g               # selector = the called member
        elif recv_node is None and ch.is_named:
            recv_node = ch                # first named child = receiver
    callee = _t(sel, src) if sel is not None else ""
    recv = _t(recv_node, src) if recv_node is not None else ""
    return callee, recv


def call_parts(node, src):
    """return (callee, recv, [arg_nodes])"""
    nav = None
    bare = None
    suffix = None
    for ch in node.children:
        if ch.type == "navigation_expression":
            nav = ch
        elif ch.type == "call_suffix":
            suffix = ch
        elif bare is None and ch.type in IDENT_TYPES:
            bare = ch

    callee, recv = "", ""
    if nav is not None:
        callee, recv = _nav_callee_recv(nav, src)
    elif bare is not None:
        callee = _t(bare, src)
    else:
        # fallback: first named non-suffix child is the callee expression
        for ch in node.children:
            if ch.type != "call_suffix" and ch.is_named:
                callee = _t(ch, src)
                break

    args = []
    if suffix is not None:
        for ch in suffix.children:
            if ch.type == "value_arguments":
                for va in ch.named_children:
                    if va.type == "value_argument":
                        args.append(va)
    return callee, recv, args


def assign_parts(node, src):
    """return (lhs_names, [rhs_nodes])

    property_declaration: name(s) come from the variable_declaration; rhs is
    the initializer after `=`. assignment: lhs base identifier of the
    directly_assignable_expression; rhs is the value after the operator.
    """
    names = []
    rhs = []
    seen_op = False
    for ch in node.children:
        if not seen_op and (ch.type in _ASSIGN_OPS):
            seen_op = True
            continue
        if not seen_op:
            if ch.type in ("variable_declaration", "multi_variable_declaration"):
                _var_decl_names(ch, src, names)
            elif ch.type == "directly_assignable_expression":
                # base identifier (e.g. `obj` in obj.field = ...)
                for g in ch.children:
                    if g.type == "simple_identifier":
                        names.append(_t(g, src))
                        break
            elif ch.type == "simple_identifier":
                names.append(_t(ch, src))
        else:
            if ch.is_named:
                rhs.append(ch)
    return [n for n in names if n != "_"], rhs


def return_vals(node):
    return [c for c in node.named_children]


_SOURCE_ANNOS = {"RequestParam","PathVariable","RequestBody","RequestHeader","CookieValue","RequestPart","ModelAttribute"}


def source_params(node, src):
    """Parameter names carrying a framework source annotation (Spring @RequestParam /
    @PathVariable / @RequestBody / …) — these are untrusted request input."""
    p = node.child_by_field_name("parameters")
    if p is None:
        return []
    out = []
    for ch in p.named_children:
        if ch.type not in ("formal_parameter", "spread_parameter"):
            continue
        hit = False
        for g in ch.children:
            if g.type == "modifiers":
                for a in g.children:
                    if a.type in ("marker_annotation", "annotation"):
                        nm = a.child_by_field_name("name")
                        if nm is not None and _t(nm, src).split(".")[-1] in _SOURCE_ANNOS:
                            hit = True
        if hit:
            idn = ch.child_by_field_name("name")
            if idn is not None:
                out.append(_t(idn, src))
    return out
