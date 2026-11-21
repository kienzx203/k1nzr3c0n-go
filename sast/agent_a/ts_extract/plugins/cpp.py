"""C/C++ plugin for the tree-sitter extractor.

Maps the tree-sitter `cpp` grammar's node types to the roles the generic
driver (extract.py) expects. Modeled on plugins/python.py (the REFERENCE),
with C/C++-specific handling for:

  * function names nested inside `function_declarator` -> `declarator`,
  * parameter names nested inside pointer/reference declarators,
  * `init_declarator` (`T x = e;`) treated as an assignment,
  * callee/recv for `field_expression` (`a.b` / `a->b`) and
    `qualified_identifier` (`std::system`).
"""

TS_LANG = "cpp"
EXTS = [".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"]

FUNC_TYPES = {"function_definition"}
LAMBDA_TYPES = {"lambda_expression"}
CLASS_TYPES = {"class_specifier", "struct_specifier"}
CALL_TYPES = {"call_expression", "subscript_expression",
              # new C(args) is a constructor call — capture it so a tainted value
              # passed to a constructor (or a constructor that is itself a sink) is seen.
              "new_expression"}
# CLI / env source identifiers that, when indexed (argv[i], environ[i]), should
# surface as a source — argv[] is the dominant C untrusted-input idiom.
_SUBSCRIPT_SOURCES = {"argv", "environ", "_environ", "envp", "__environ"}
# init_declarator (`std::string x = e`) is handled as an assignment alongside
# the real assignment_expression node.
ASSIGN_TYPES = {"assignment_expression", "init_declarator"}
RETURN_TYPES = {"return_statement"}
STRING_TYPES = {"string_literal", "raw_string_literal"}
BINARY_TYPES = {"binary_expression"}
IDENT_TYPES = {"identifier", "field_identifier"}
MEMBER_TYPES = {"field_expression"}

# declarator wrappers we transparently descend through to reach the real name
_DECL_WRAPPERS = {
    "pointer_declarator", "reference_declarator", "parenthesized_declarator",
    "array_declarator", "init_declarator",
}


def _t(n, src):
    return src[n.start_byte:n.end_byte].decode("utf-8", "replace")


def pkg_name(root, src, path):
    import os
    return os.path.splitext(os.path.basename(path))[0]


def is_concat(node, src):
    # a '+' binary operator (std::string concatenation)
    for ch in node.children:
        if ch.type == "+" or _t(ch, src) == "+":
            return True
    return False


# ---------------------------------------------------------------------------
# declarator helpers
# ---------------------------------------------------------------------------
def _function_declarator(node):
    """From a function_definition (or declaration), follow the `declarator`
    field chain down to the `function_declarator` node."""
    d = node.child_by_field_name("declarator")
    seen = 0
    while d is not None and seen < 20:
        if d.type == "function_declarator":
            return d
        d = d.child_by_field_name("declarator")
        seen += 1
    return None


def _param_list(node):
    """Locate the parameter_list for a function_definition or a
    lambda_expression by walking the declarator chain (function_declarator /
    lambda_declarator both expose a `parameters` field)."""
    d = node.child_by_field_name("declarator")
    seen = 0
    while d is not None and seen < 20:
        p = d.child_by_field_name("parameters")
        if p is not None:
            return p
        d = d.child_by_field_name("declarator")
        seen += 1
    return None


def _decl_ident(n, src):
    """Descend a declarator subtree to the bound identifier it introduces,
    skipping pointer/reference/array wrappers (`char* p`, `const T& x`...)."""
    seen = 0
    while n is not None and seen < 20:
        if n.type in ("identifier", "field_identifier"):
            return _t(n, src)
        nxt = n.child_by_field_name("declarator")
        if nxt is None:
            for c in n.children:
                if c.type in ("identifier", "field_identifier"):
                    return _t(c, src)
            return ""
        n = nxt
        seen += 1
    return ""


def _last_name(n, src):
    """Resolve the final name of a (possibly nested) qualified_identifier."""
    seen = 0
    while n is not None and n.type == "qualified_identifier" and seen < 20:
        nm = n.child_by_field_name("name")
        if nm is None:
            break
        n = nm
        seen += 1
    return _t(n, src) if n is not None else ""


# ---------------------------------------------------------------------------
# roles
# ---------------------------------------------------------------------------
def func_name(node, src):
    """C/C++ function name lives inside function_declarator -> declarator."""
    fd = _function_declarator(node)
    if fd is None:
        return ""
    d = fd.child_by_field_name("declarator")
    return _t(d, src) if d is not None else ""


def func_params(node, src):
    pl = _param_list(node)
    names = []
    if pl is None:
        return names
    for ch in pl.named_children:
        if ch.type in ("parameter_declaration", "optional_parameter_declaration"):
            d = ch.child_by_field_name("declarator")
            nm = _decl_ident(d, src) if d is not None else ""
            if nm:
                names.append(nm)
    return names


def func_body(node):
    # compound_statement for both function_definition and lambda_expression
    return node.child_by_field_name("body")


def class_name(node, src):
    n = node.child_by_field_name("name")
    return _t(n, src) if n is not None else ""


def call_parts(node, src):
    """return (callee, recv, [arg_nodes]).

    recv is set to the FULL object/qualifier text so sink regexes such as
    system/popen/exec/sprintf/fopen/strcpy still match on `callee`, and
    source/sink patterns that look at `full` keep working.
    """
    # argv[i] / environ[i] subscript → surface base as callee so a source sig matches;
    # an ordinary array index (arr[i]) returns no callee (not a source).
    if node.type == "subscript_expression":
        nc = node.named_children
        base = nc[0] if nc else None
        if base is not None and base.type == "identifier" and _t(base, src) in _SUBSCRIPT_SOURCES:
            return _t(base, src), "", []
        # arr[index]: surface the INDEX expression so a tainted/attacker-controlled index
        # (CWE-129 out-of-bounds array access) is caught. A constant index is safe → no args.
        idx = nc[1] if len(nc) > 1 else None
        if idx is not None and idx.type not in ("number_literal", "char_literal"):
            return "array_index", (_t(base, src) if base is not None else ""), [idx]
        return "", "", []
    if node.type == "new_expression":
        ty = node.child_by_field_name("type")
        anode = node.child_by_field_name("arguments")
        aargs = list(anode.named_children) if anode is not None else []
        return (_last_name(ty, src) if ty is not None else ""), "", aargs
    fn = node.child_by_field_name("function")
    args_node = node.child_by_field_name("arguments")
    args = list(args_node.named_children) if args_node else []
    callee, recv = "", ""
    if fn is None:
        return callee, recv, args
    if fn.type == "field_expression":
        # obj.method(...) / obj->method(...)  -> callee=field, recv=full object
        field = fn.child_by_field_name("field")
        obj = fn.child_by_field_name("argument")
        callee = _t(field, src) if field is not None else ""
        recv = _t(obj, src) if obj is not None else ""
    elif fn.type == "qualified_identifier":
        # std::system  -> callee=last name, recv=the qualifier
        name = fn.child_by_field_name("name")
        scope = fn.child_by_field_name("scope")
        callee = _last_name(name, src) if name is not None else _t(fn, src)
        recv = _t(scope, src) if scope is not None else ""
    elif fn.type == "identifier":
        callee = _t(fn, src)
    else:
        # template_function (foo<T>) and anything else: use raw text
        callee = _t(fn, src)
    return callee, recv, args


def assign_parts(node, src):
    """return (lhs_names, [rhs_nodes]) for assignment_expression and
    init_declarator (`T x = e` -> lhs=x, rhs=e)."""
    names = []
    if node.type == "init_declarator":
        d = node.child_by_field_name("declarator")
        v = node.child_by_field_name("value")
        nm = _decl_ident(d, src) if d is not None else ""
        if nm:
            names.append(nm)
        return names, ([v] if v is not None else [])

    # assignment_expression
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is not None:
        stack = [left]
        while stack:
            x = stack.pop()
            if x.type in ("identifier", "field_identifier"):
                names.append(_t(x, src))
            elif x.type == "field_expression":
                obj = x.child_by_field_name("argument")
                if obj is not None and obj.type == "identifier":
                    names.append(_t(obj, src))
            elif x.type == "subscript_expression":
                obj = x.child_by_field_name("argument")
                if obj is not None and obj.type == "identifier":
                    names.append(_t(obj, src))
            else:
                stack.extend(x.children)
    rhs = [right] if right is not None else []
    return [n for n in names if n != "_"], rhs


def return_vals(node):
    return [c for c in node.named_children]
