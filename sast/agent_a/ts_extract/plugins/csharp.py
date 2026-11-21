"""C# plugin for the tree-sitter extractor.

Maps the tree-sitter-c-sharp grammar's node types to the language-agnostic
roles consumed by extract.py (see plugins/python.py for the reference).

Grammar notes (verified via tree_sitter_language_pack "csharp"):
  * method/constructor/local-function declarations carry fields
    ``name`` / ``parameters`` / ``body``; each ``parameter`` has a ``name``.
  * ``invocation_expression`` has fields ``function`` + ``arguments``; when the
    callee is a ``member_access_expression`` (``a.b``) it exposes ``expression``
    (the receiver) and ``name`` (the member).
  * ``object_creation_expression`` (``new T(...)``) exposes field ``type``.
  * ``element_access_expression`` (``Request.QueryString["n"]``) exposes
    ``expression`` (the indexed object) + ``subscript``. It is treated as a
    call so indexer *sources* like ``Request.QueryString[...]`` are matched by
    the taint engine (sources are only ever matched against call IR nodes).
  * interpolated strings (``$"..{x}.."``) are treated as concatenation.
"""

import os

TS_LANG = "csharp"
EXTS = [".cs"]

FUNC_TYPES = {
    "method_declaration",
    "constructor_declaration",
    "local_function_statement",
    "destructor_declaration",
    "operator_declaration",
    "conversion_operator_declaration",
    "accessor_declaration",
}
LAMBDA_TYPES = {"lambda_expression", "anonymous_method_expression"}
CLASS_TYPES = {
    "class_declaration",
    "struct_declaration",
    "record_declaration",
    "record_struct_declaration",
    "interface_declaration",
}
# element_access_expression is included so that indexer sources such as
# `Request.QueryString["n"]` / `r.Query["n"]` surface as call IR nodes.
CALL_TYPES = {
    "invocation_expression",
    "object_creation_expression",
    "element_access_expression",
}
ASSIGN_TYPES = {"assignment_expression", "variable_declarator"}
RETURN_TYPES = {"return_statement"}
STRING_TYPES = {
    "string_literal",
    "verbatim_string_literal",
    "raw_string_literal",
    "interpolated_string_expression",
    "interpolated_verbatim_string_expression",
}
# f-string-style interpolation -> treat as concatenation (tainted-into-string)
INTERP_TYPES = {
    "interpolated_string_expression",
    "interpolated_verbatim_string_expression",
}
BINARY_TYPES = {"binary_expression"}
IDENT_TYPES = {"identifier"}
MEMBER_TYPES = {"member_access_expression"}


def _t(n, src):
    return src[n.start_byte:n.end_byte].decode("utf-8", "replace")


def pkg_name(root, src, path):
    return os.path.splitext(os.path.basename(path))[0]


def is_concat(node, src):
    # a '+' binary operator (string concatenation)
    for ch in node.children:
        if ch.type == "+" or _t(ch, src) == "+":
            return True
    return False


def func_name(node, src):
    n = node.child_by_field_name("name")
    return _t(n, src) if n else ""


def _param_names(plist, src):
    names = []
    if plist is None:
        return names
    for ch in plist.named_children:
        if ch.type == "parameter":
            idn = ch.child_by_field_name("name")
            if idn is None:
                for g in ch.children:
                    if g.type == "identifier":
                        idn = g
                        break
            if idn is not None:
                names.append(_t(idn, src))
        elif ch.type == "identifier":
            # bare lambda parameter, e.g. `x => ...`
            names.append(_t(ch, src))
    return names


def func_params(node, src):
    p = node.child_by_field_name("parameters")
    if p is None:
        # lambdas / anonymous methods may carry a parameter_list without a field
        for ch in node.children:
            if ch.type == "parameter_list":
                p = ch
                break
    if p is None and node.type == "lambda_expression":
        # single bare parameter: `x => ...`
        for ch in node.children:
            if ch.type == "identifier":
                return [_t(ch, src)]
    return _param_names(p, src)


def func_body(node):
    b = node.child_by_field_name("body")
    if b is not None:
        return b
    # anonymous_method_expression (`delegate { ... }`) has no body field
    for ch in node.children:
        if ch.type in ("block", "arrow_expression_clause"):
            return ch
    return None


def class_name(node, src):
    # Intentionally return "" so methods are NOT scoped by a receiver type.
    #
    # The tree-sitter frontend does no type inference, so typed receiver
    # resolution (`x.M()` with x:T -> T.M) can never fire. Meanwhile C# calls a
    # same-class method WITHOUT an explicit receiver (`RunQuery(x)`, not
    # `this.RunQuery(x)` as Python needs `self.`). If methods carried a
    # recvType, the call graph would file them under `_methods` (keyed by type)
    # and such bare same-class calls — the dominant C# pattern — would never
    # resolve, breaking inter-procedural taint. Treating them as receiver-less
    # files them under `_plain`, so both bare and receiver-qualified internal
    # calls resolve by name (an over-approximation, which is the safe bias for
    # a taint engine). The cost is that function keys are not class-qualified.
    return ""


def _simple_name(node, src):
    """Last identifier of a (possibly qualified / generic) type/name node."""
    if node is None:
        return ""
    nm = node.child_by_field_name("name")
    if nm is not None:
        return _simple_name(nm, src)
    if node.type == "qualified_name":
        # qualifier . name  -> take the trailing name
        last = node.named_children[-1] if node.named_children else None
        return _simple_name(last, src) if last is not None else _t(node, src)
    if node.type == "generic_name":
        for ch in node.children:
            if ch.type == "identifier":
                return _t(ch, src)
    return _t(node, src)


def _arg_list(node):
    """Find the argument-bearing child list for a call-like node."""
    a = node.child_by_field_name("arguments")
    if a is not None:
        return a
    a = node.child_by_field_name("subscript")      # element_access
    if a is not None:
        return a
    for ch in node.children:
        if ch.type in ("argument_list", "bracketed_argument_list"):
            return ch
    return None


def _member_parts(member, src):
    """(callee, recv) for a member_access_expression `expr.name`."""
    expr = member.child_by_field_name("expression")
    name = member.child_by_field_name("name")
    callee = _t(name, src) if name is not None else ""
    recv = _t(expr, src) if expr is not None else ""
    return callee, recv


def call_parts(node, src):
    """return (callee, recv, [arg_nodes])"""
    args_node = _arg_list(node)
    args = list(args_node.named_children) if args_node else []
    callee, recv = "", ""

    if node.type == "object_creation_expression":
        # `new SqlCommand(...)` -> callee is the type name so sinks like
        # `SqlCommand` match; no receiver.
        ty = node.child_by_field_name("type")
        if ty is None:
            for ch in node.children:
                if ch.type not in ("new", "argument_list", "initializer_expression"):
                    ty = ch
                    break
        callee = _simple_name(ty, src) if ty is not None else ""
        return callee, "", args

    if node.type == "element_access_expression":
        # `Request.QueryString["n"]` -> callee=QueryString, recv=Request so the
        # engine's `full` ("Request.QueryString") matches indexer sources.
        obj = node.child_by_field_name("expression")
        if obj is not None and obj.type == "member_access_expression":
            callee, recv = _member_parts(obj, src)
        elif obj is not None and obj.type == "identifier":
            callee = _t(obj, src)
        elif obj is not None:
            callee = _t(obj, src)
        return callee, recv, args

    # invocation_expression
    fn = node.child_by_field_name("function")
    if fn is None:
        return callee, recv, args
    if fn.type == "member_access_expression":
        # callee = member name; recv = FULL text of the receiver expression so
        # sources/sinks like `cmd.ExecuteReader`, `Process.Start`,
        # `File.ReadAllText`, `Request.QueryString.Get` match on `full`.
        callee, recv = _member_parts(fn, src)
    elif fn.type == "identifier":
        callee = _t(fn, src)
    elif fn.type in ("generic_name", "qualified_name"):
        callee = _simple_name(fn, src)
    else:
        callee = _t(fn, src)
    return callee, recv, args


def assign_parts(node, src):
    """return (lhs_names, [rhs_nodes])"""
    names, rhs = [], []

    if node.type == "variable_declarator":
        # `var x = <init>` : lhs = declarator name, rhs = initializer value
        nm = node.child_by_field_name("name")
        if nm is not None:
            names.append(_t(nm, src))
        else:
            for ch in node.children:
                if ch.type == "identifier":
                    names.append(_t(ch, src))
                    break
        val = node.child_by_field_name("value")
        if val is None:
            # initializer is the node following the '=' token
            seen_eq = False
            for ch in node.children:
                if ch.type == "=":
                    seen_eq = True
                    continue
                if seen_eq and ch.is_named:
                    val = ch
                    break
        if val is not None:
            rhs = [val]
        return [n for n in names if n != "_"], rhs

    # assignment_expression: left = / += ... right
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is not None:
        stack = [left]
        while stack:
            x = stack.pop()
            if x.type == "identifier":
                names.append(_t(x, src))
            elif x.type == "member_access_expression":
                expr = x.child_by_field_name("expression")
                if expr is not None and expr.type == "identifier":
                    names.append(_t(expr, src))
            elif x.type == "element_access_expression":
                expr = x.child_by_field_name("expression")
                if expr is not None and expr.type == "identifier":
                    names.append(_t(expr, src))
            else:
                stack.extend(x.children)
    if right is not None:
        rhs = [right]
    return [n for n in names if n != "_"], rhs


def return_vals(node):
    return [c for c in node.named_children]
