"""Python plugin for the tree-sitter extractor (REFERENCE implementation).

A plugin maps a grammar's node types to roles. Copy this file for a new language
and adjust the node-type names + the *_parts helpers to that grammar.
"""

TS_LANG = "python"
EXTS = [".py"]

FUNC_TYPES = {"function_definition"}
LAMBDA_TYPES = {"lambda"}
CLASS_TYPES = {"class_definition"}
CALL_TYPES = {"call"}
ASSIGN_TYPES = {"assignment", "augmented_assignment", "named_expression"}
RETURN_TYPES = {"return_statement"}
STRING_TYPES = {"string"}
INTERP_TYPES = {"interpolation"}        # f-string parts -> treat as concat/taint
BINARY_TYPES = {"binary_operator"}
IDENT_TYPES = {"identifier"}


def _t(n, src):
    return src[n.start_byte:n.end_byte].decode("utf-8", "replace")


MEMBER_TYPES = {"attribute"}


def member_path(node, src):
    """Dotted field path (self.a.b) for field-sensitivity."""
    o = node.child_by_field_name("object")
    at = node.child_by_field_name("attribute")
    name = _t(at, src) if at is not None else ""
    if o is None or not name:
        return None
    base = member_path(o, src) if o.type == "attribute" else _t(o, src)
    return (base + "." + name) if base else None


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


def func_params(node, src):
    p = node.child_by_field_name("parameters")
    names = []
    if not p:
        return names
    for ch in p.named_children:
        if ch.type == "identifier":
            names.append(_t(ch, src))
        elif ch.type in ("default_parameter", "typed_parameter",
                         "typed_default_parameter", "list_splat_pattern",
                         "dictionary_splat_pattern"):
            idn = ch.child_by_field_name("name")
            if idn is None:
                for g in ch.children:
                    if g.type == "identifier":
                        idn = g
                        break
            if idn is not None:
                names.append(_t(idn, src))
    return [n for n in names if n != "self"]


def func_body(node):
    return node.child_by_field_name("body")


def class_name(node, src):
    n = node.child_by_field_name("name")
    return _t(n, src) if n else ""


def call_parts(node, src):
    """return (callee, recv, [arg_nodes])"""
    fn = node.child_by_field_name("function")
    args_node = node.child_by_field_name("arguments")
    args = list(args_node.named_children) if args_node else []
    callee, recv = "", ""
    if fn is None:
        return callee, recv, args
    if fn.type == "attribute":
        obj = fn.child_by_field_name("object")
        attr = fn.child_by_field_name("attribute")
        callee = _t(attr, src) if attr else ""
        # full object text so source/sink regexes like request.args / os.system match
        recv = _t(obj, src) if obj else ""
    elif fn.type == "identifier":
        callee = _t(fn, src)
    else:
        callee = _t(fn, src)
    return callee, recv, args


def assign_parts(node, src):
    """return (lhs_names, [rhs_nodes])"""
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    names = []
    if left is not None:
        stack = [left]
        while stack:
            x = stack.pop()
            if x.type == "identifier":
                names.append(_t(x, src))
            elif x.type == "attribute":
                mp = member_path(x, src)      # field-sensitive: self.a -> 'self.a'
                if mp:
                    names.append(mp)
            elif x.type in ("subscript",):
                obj = x.child_by_field_name("value")
                if obj is not None and obj.type == "identifier":
                    names.append(_t(obj, src))
            else:
                stack.extend(x.children)
    rhs = [right] if right is not None else []
    return [n for n in names if n != "_"], rhs


def return_vals(node):
    return [c for c in node.named_children]
