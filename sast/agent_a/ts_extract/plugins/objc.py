"""Objective-C plugin for the tree-sitter extractor (tree-sitter `objc` grammar)."""

TS_LANG = "objc"
EXTS = [".m", ".mm"]

FUNC_TYPES = {"method_definition", "function_definition", "class_method_definition",
              "instance_method_definition"}
LAMBDA_TYPES = {"block_expression"}
CLASS_TYPES = {"class_implementation", "class_interface", "category_implementation"}
CALL_TYPES = {"message_expression", "call_expression", "subscript_expression"}
# argv[i] / environ[i] are untrusted-input reads (CLI args / environment).
_SUBSCRIPT_SOURCES = {"argv", "environ", "_environ", "envp", "__environ"}
ASSIGN_TYPES = {"assignment_expression", "init_declarator"}
RETURN_TYPES = {"return_statement"}
STRING_TYPES = {"string_literal"}
INTERP_TYPES = set()
BINARY_TYPES = {"binary_expression"}
IDENT_TYPES = {"identifier"}


def _t(n, src):
    return src[n.start_byte:n.end_byte].decode("utf-8", "replace")


def pkg_name(root, src, path):
    import os
    return os.path.splitext(os.path.basename(path))[0]


def is_concat(node, src):
    for ch in node.children:
        if _t(ch, src) == "+":
            return True
    return False


def _first_ident(node, src):
    for ch in node.children:
        if ch.type == "identifier":
            return _t(ch, src)
    return ""


def _declarator(node):
    # C function: function_definition -> function_declarator (holds name + params)
    for ch in node.children:
        if ch.type == "function_declarator":
            return ch
    return None


def _last_ident(node, src):
    """Deepest/last identifier under a (possibly pointer-wrapped) declarator — the
    bound NAME, e.g. `NSString* c` -> `c` (not the type `NSString`)."""
    found = [None]
    def walk(n):
        if n.type == "identifier":
            found[0] = n
        for c in n.children:
            walk(c)
    walk(node)
    return _t(found[0], src) if found[0] is not None else ""


def func_name(node, src):
    # message selector name: the first direct-child identifier of the method def
    n = node.child_by_field_name("selector")
    if n is not None:
        return _t(n, src)
    # plain C function: name is the identifier inside function_declarator
    decl = _declarator(node)
    if decl is not None:
        for g in decl.children:
            if g.type == "identifier":
                return _t(g, src)
    return _first_ident(node, src)


def func_params(node, src):
    names = []
    # C function params live inside function_declarator -> parameter_list
    decl = _declarator(node)
    scope = []
    if decl is not None:
        for g in decl.children:
            if g.type == "parameter_list":
                scope = g.named_children
    if not scope:
        scope = node.named_children
    for ch in scope:
        if ch.type in ("method_parameter", "parameter_declaration", "parameter"):
            nm = _last_ident(ch, src)   # the param name (declarator identifier)
            if nm:
                names.append(nm)
    return names


def func_body(node):
    for ch in node.named_children:
        if ch.type == "compound_statement":
            return ch
    return node.child_by_field_name("body")


def class_name(node, src):
    return _first_ident(node, src)


def call_parts(node, src):
    callee, recv, args = "", "", []
    # argv[i] / environ[i] subscript → surface base as callee so a source sig matches;
    # an ordinary array index (arr[i]) returns no callee (not a source).
    if node.type == "subscript_expression":
        nc = node.named_children
        base = nc[0] if nc else None
        if base is not None and base.type == "identifier" and _t(base, src) in _SUBSCRIPT_SOURCES:
            return _t(base, src), "", []
        idx = nc[1] if len(nc) > 1 else None
        if idx is not None and idx.type not in ("number_literal", "char_literal"):
            return "array_index", (_t(base, src) if base is not None else ""), [idx]
        return "", "", []
    if node.type == "message_expression":
        rc = node.child_by_field_name("receiver")
        mt = node.child_by_field_name("method")
        recv = _t(rc, src) if rc else ""
        callee = _t(mt, src) if mt else ""
        skip = {rc, mt}
        for ch in node.named_children:
            if ch in skip:
                continue
            args.append(ch)
    else:  # call_expression (plain C call)
        fn = node.child_by_field_name("function")
        callee = _t(fn, src) if fn else ""
        al = node.child_by_field_name("arguments")
        if al is not None:
            args = list(al.named_children)
    return callee, recv, args


def assign_parts(node, src):
    names, rhs = [], []
    if node.type == "init_declarator":
        dec = node.child_by_field_name("declarator")
        val = node.child_by_field_name("value")
        if dec is not None:
            stack = [dec]
            while stack:
                x = stack.pop()
                if x.type == "identifier":
                    names.append(_t(x, src)); break
                stack.extend(x.children)
        if val is not None:
            rhs = [val]
    else:  # assignment_expression
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is not None:
            if left.type == "identifier":
                names.append(_t(left, src))
            else:
                names.append(_first_ident(left, src))
        if right is not None:
            rhs = [right]
    return [n for n in names if n], rhs


def return_vals(node):
    return [c for c in node.named_children]
