"""TypeScript plugin for the tree-sitter extractor.

Standalone implementation (does not depend on a javascript plugin). The
TypeScript grammar is the JavaScript grammar plus type nodes; this plugin maps
the relevant node types to the roles the generic driver (extract.py) expects.

Notable design point for the JS/TS family: taint SOURCES in the taint_spec DB
are *property accesses* (``req.query``, ``location.search``, ``document.cookie``,
``URLSearchParams``), not method calls. The engine only matches a source against
a call node's ``full``/``callee`` text, so ``member_expression`` is included in
CALL_TYPES: a member access becomes a zero-arg "call" whose ``full`` is the
dotted path (e.g. ``req.query.name``), which lets the source regexes fire. The
driver's call counter uses this same CALL_TYPES set, so ``call_seen`` and
``call_total`` stay in agreement (the framework only double-counts calls that
are nested inside another call's arguments).
"""

TS_LANG = "typescript"
EXTS = [".ts", ".tsx"]

FUNC_TYPES = {
    "function_declaration",
    "generator_function_declaration",
    "function_expression",
    "generator_function",
    "method_definition",
}
LAMBDA_TYPES = {"arrow_function"}
CLASS_TYPES = {"class_declaration", "class", "abstract_class_declaration"}
# member_expression is a "call" so property-access sources (req.query, ...) match
CALL_TYPES = {"call_expression", "new_expression", "member_expression"}
ASSIGN_TYPES = {
    "assignment_expression",
    "augmented_assignment_expression",
    "variable_declarator",
}
RETURN_TYPES = {"return_statement"}
STRING_TYPES = {"string", "template_string"}
INTERP_TYPES = {"template_substitution"}        # `${x}` -> treat as concat/taint
BINARY_TYPES = {"binary_expression"}
IDENT_TYPES = {"identifier", "property_identifier"}


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


def _pattern_names(n, src):
    """Collect bound identifier names from a parameter/assignment target,
    ignoring any type annotation. Handles plain identifiers, member/subscript
    targets (base object), and destructuring (array/object patterns)."""
    names = []
    if n is None:
        return names
    t = n.type
    if t in ("identifier", "shorthand_property_identifier",
             "shorthand_property_identifier_pattern"):
        names.append(_t(n, src))
    elif t in ("member_expression", "subscript_expression"):
        obj = n.child_by_field_name("object")
        prop = n.child_by_field_name("property")
        # unwrap (x as T) / (x) / x! casts so `(el as any).innerHTML` still resolves
        base = obj
        while base is not None and base.type in (
                "parenthesized_expression", "as_expression",
                "non_null_expression", "satisfies_expression"):
            base = base.child_by_field_name("expression") or (
                base.named_children[0] if base.named_children else None)
        if base is not None and base.type == "identifier":
            # keep the full dotted path (el.innerHTML) so a DOM-assignment sink matches
            if t == "member_expression" and prop is not None:
                names.append(_t(base, src) + "." + _t(prop, src))
            else:
                names.append(_t(base, src))
    else:
        # array_pattern / object_pattern / rest_pattern / assignment_pattern ...
        stack = list(n.children)
        while stack:
            x = stack.pop()
            xt = x.type
            if xt == "type_annotation":
                continue                       # drop the ": T" part
            if xt in ("identifier", "shorthand_property_identifier",
                      "shorthand_property_identifier_pattern"):
                names.append(_t(x, src))
            elif xt in ("pair_pattern", "object_assignment_pattern",
                        "rest_pattern", "array_pattern", "object_pattern",
                        "assignment_pattern"):
                stack.extend(x.children)
    return names


def func_name(node, src):
    n = node.child_by_field_name("name")
    return _t(n, src) if n else ""


def func_params(node, src):
    p = node.child_by_field_name("parameters")
    names = []
    if p is None:
        # arrow with a single un-parenthesised param: (x => ...) is still
        # wrapped in formal_parameters by this grammar, so this is rare.
        return names
    for ch in p.named_children:
        t = ch.type
        if t == "identifier":
            names.append(_t(ch, src))
        elif t in ("required_parameter", "optional_parameter"):
            pat = ch.child_by_field_name("pattern")
            names += _pattern_names(pat, src)
        elif t == "rest_pattern":
            names += _pattern_names(ch, src)
        else:
            names += _pattern_names(ch, src)
    return [n for n in names if n not in ("this",)]


def func_body(node):
    # function_declaration/method_definition -> statement_block;
    # arrow_function -> statement_block OR a bare expression (both via "body").
    return node.child_by_field_name("body")


def class_name(node, src):
    n = node.child_by_field_name("name")
    return _t(n, src) if n else ""


def call_parts(node, src):
    """return (callee, recv, [arg_nodes]).

    member call  -> callee=property name, recv=FULL object text (so dotted
                    source/sink regexes like req.query / child_process.exec match)
    plain call   -> callee=function identifier
    member access-> treated as a zero-arg call with full dotted path
    """
    t = node.type

    # bare member access used as a source (req.query.name, location.search, ...)
    if t == "member_expression":
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        callee = _t(prop, src) if prop is not None else ""
        recv = _t(obj, src) if obj is not None else ""
        return callee, recv, []

    # call_expression -> field "function"; new_expression -> field "constructor"
    fn = node.child_by_field_name("function")
    if fn is None:
        fn = node.child_by_field_name("constructor")
    args_node = node.child_by_field_name("arguments")
    args = list(args_node.named_children) if args_node else []

    callee, recv = "", ""
    if fn is None:
        return callee, recv, args
    if fn.type == "member_expression":
        obj = fn.child_by_field_name("object")
        prop = fn.child_by_field_name("property")
        callee = _t(prop, src) if prop is not None else ""
        # full object text so source/sink regexes match the whole chain
        recv = _t(obj, src) if obj is not None else ""
    else:
        callee = _t(fn, src)
    return callee, recv, args


def assign_parts(node, src):
    """return (lhs_names, [rhs_nodes])."""
    if node.type == "variable_declarator":
        name = node.child_by_field_name("name")
        val = node.child_by_field_name("value")
        names = _pattern_names(name, src)
        rhs = [val] if val is not None else []
        return [n for n in names if n != "_"], rhs

    # assignment_expression / augmented_assignment_expression
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    names = _pattern_names(left, src)
    rhs = [right] if right is not None else []
    return [n for n in names if n != "_"], rhs


def return_vals(node):
    return [c for c in node.named_children]
