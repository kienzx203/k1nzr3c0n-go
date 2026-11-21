"""JavaScript plugin for the tree-sitter extractor.

Maps the tree-sitter-javascript grammar's node types to the roles the generic
driver (extract.py) understands. Mirrors the structure of python.py.

Key design points for JS:
- `member_expression` is treated as a CALL node too, so a *bare* property read
  such as `req.query.name` is surfaced to the taint engine with a matchable
  `full` ("req.query.name"). The engine only matches sources/sinks against call
  IR nodes (callee/full), so without this an Express source like `req.query.name`
  would never be recognised. `call_parts` returns no args for a bare member read.
- For a `call_expression` / `new_expression` whose callee is a member_expression,
  `callee` is the property text and `recv` is the FULL object text, so
  `child_process.exec`, `req.query.get`, `res.send`, `db.query` all match the
  JS taint-spec regexes (exec / req.query / query / ...).
- Arrow functions and function expressions are both treated as lambdas (anon,
  linked to their enclosing function for closure/captured-variable taint) and
  also as top-level function types so Express handlers passed as callback
  arguments (`app.get('/', function (req, res) {...})`) still get a body.
"""

TS_LANG = "javascript"
EXTS = [".js", ".mjs", ".jsx"]

# Named definitions driven top-level by extract.run(); arrow/function-expression
# are also listed so handlers passed as callbacks at module scope get analysed.
FUNC_TYPES = {
    "function_declaration",
    "generator_function_declaration",
    "method_definition",
    "function_expression",
    "generator_function",
    "arrow_function",
}
# Expression-form functions -> built as anon nodes by extract.expr() so captured
# (free) variables flow through closures.
LAMBDA_TYPES = {"arrow_function", "function_expression", "generator_function"}
CLASS_TYPES = {"class_declaration", "class"}
# member_expression included so bare property reads are matchable sources/sinks.
CALL_TYPES = {"call_expression", "new_expression", "member_expression"}
ASSIGN_TYPES = {
    "assignment_expression",
    "augmented_assignment_expression",
    "variable_declarator",
}
RETURN_TYPES = {"return_statement"}
STRING_TYPES = {"string", "template_string"}
INTERP_TYPES = {"template_substitution"}   # `${...}` -> treat as concat/taint
BINARY_TYPES = {"binary_expression"}
IDENT_TYPES = {
    "identifier",
    "property_identifier",
    "shorthand_property_identifier",
    "shorthand_property_identifier_pattern",
}


def _t(n, src):
    return src[n.start_byte:n.end_byte].decode("utf-8", "replace")


def pkg_name(root, src, path):
    import os
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


def _collect_params(node, src, out):
    """Collect bound parameter names, skipping default *values*."""
    t = node.type
    if t in ("identifier", "shorthand_property_identifier_pattern",
             "shorthand_property_identifier"):
        out.append(_t(node, src))
        return
    if t == "assignment_pattern":                 # a = default  -> take `a` only
        left = node.child_by_field_name("left")
        if left is not None:
            _collect_params(left, src, out)
        return
    if t == "pair_pattern":                        # {k: v} -> take the bound `v`
        val = node.child_by_field_name("value")
        if val is not None:
            _collect_params(val, src, out)
        return
    if t in ("rest_pattern", "object_pattern", "array_pattern",
             "required_parameter", "optional_parameter"):
        for ch in node.named_children:
            _collect_params(ch, src, out)
        return


def func_params(node, src):
    p = node.child_by_field_name("parameters")
    names = []
    if p is None:
        # arrow with a single bare identifier param: `x => ...`
        for ch in node.named_children:
            if ch.type == "identifier":
                names.append(_t(ch, src))
                break
        return names
    for ch in p.named_children:
        _collect_params(ch, src, names)
    return [n for n in names if n not in ("this",)]


def func_body(node):
    # statement_block for declarations/blocks; an expression for concise arrows.
    return node.child_by_field_name("body")


def class_name(node, src):
    n = node.child_by_field_name("name")
    return _t(n, src) if n else ""


def call_parts(node, src):
    """return (callee, recv, [arg_nodes]).

    member_expression (bare read): callee=property, recv=FULL object text, no args.
    call_expression / new_expression: callee=property or identifier text,
    recv=FULL object text when the callee is a member access.
    """
    if node.type == "member_expression":
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        callee = _t(prop, src) if prop else ""
        recv = _t(obj, src) if obj else ""
        return callee, recv, []

    fn = node.child_by_field_name("function")
    if fn is None:
        fn = node.child_by_field_name("constructor")   # new_expression
    args_node = node.child_by_field_name("arguments")
    args = list(args_node.named_children) if args_node else []
    callee, recv = "", ""
    if fn is None:
        return callee, recv, args
    if fn.type == "member_expression":
        obj = fn.child_by_field_name("object")
        prop = fn.child_by_field_name("property")
        callee = _t(prop, src) if prop else ""
        recv = _t(obj, src) if obj else ""      # full object text (e.g. req.query)
    else:
        callee = _t(fn, src)                    # identifier / other callee
    return callee, recv, args


def assign_parts(node, src):
    """return (lhs_names, [rhs_nodes])"""
    if node.type == "variable_declarator":
        left = node.child_by_field_name("name")
        right = node.child_by_field_name("value")
    else:                                        # (augmented_)assignment_expression
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
    names = []
    if left is not None:
        stack = [left]
        while stack:
            x = stack.pop()
            t = x.type
            if t in ("identifier", "shorthand_property_identifier_pattern",
                     "shorthand_property_identifier"):
                names.append(_t(x, src))
            elif t == "member_expression":
                obj = x.child_by_field_name("object")
                prop = x.child_by_field_name("property")
                if obj is not None and obj.type == "identifier":
                    # keep the full dotted path (el.innerHTML) so a DOM-assignment
                    # sink (innerHTML / location / src) can match the LHS.
                    names.append(_t(obj, src) + "." + _t(prop, src) if prop is not None else _t(obj, src))
            elif t == "subscript_expression":
                obj = x.child_by_field_name("object")
                if obj is not None and obj.type == "identifier":
                    names.append(_t(obj, src))
            else:
                stack.extend(x.children)
    rhs = [right] if right is not None else []
    return [n for n in names if n != "_"], rhs


def return_vals(node):
    return [c for c in node.named_children]
