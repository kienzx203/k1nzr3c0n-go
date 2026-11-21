"""VB.NET / VB plugin for the tree-sitter extractor (tree-sitter `vb` grammar).
Taint family = dotnet (shares the .NET signature set)."""

TS_LANG = "vb"
EXTS = [".vb"]

FUNC_TYPES = {"method_declaration", "sub_declaration", "function_declaration",
              "constructor_declaration", "property_block"}
LAMBDA_TYPES = {"lambda_expression"}
CLASS_TYPES = {"class_block", "module_block", "structure_block", "type_declaration"}
CALL_TYPES = {"invocation", "new_expression"}
ASSIGN_TYPES = {"dim_statement", "assignment_statement", "local_declaration_statement"}
RETURN_TYPES = {"return_statement"}
STRING_TYPES = {"string_literal", "interpolated_string_expression"}
INTERP_TYPES = {"interpolated_string_expression"}
BINARY_TYPES = {"binary_expression"}
IDENT_TYPES = {"identifier"}


def _t(n, src):
    return src[n.start_byte:n.end_byte].decode("utf-8", "replace")


def pkg_name(root, src, path):
    import os
    return os.path.splitext(os.path.basename(path))[0]


def is_concat(node, src):
    for ch in node.children:
        if _t(ch, src) in ("&", "+"):
            return True
    return False


def func_name(node, src):
    n = node.child_by_field_name("name")
    if n is not None:
        return _t(n, src)
    for ch in node.named_children:
        if ch.type == "identifier":
            return _t(ch, src)
    return ""


def func_params(node, src):
    names = []
    pl = node.child_by_field_name("parameters")
    if pl is None:
        for ch in node.named_children:
            if ch.type == "parameter_list":
                pl = ch
                break
    if pl is not None:
        for ch in pl.named_children:
            if ch.type == "parameter":
                nm = ch.child_by_field_name("name")
                if nm is None:
                    for g in ch.named_children:
                        if g.type == "identifier":
                            nm = g
                            break
                if nm is not None:
                    names.append(_t(nm, src))
    return names


def func_body(node):
    return node


def class_name(node, src):
    n = node.child_by_field_name("name")
    return _t(n, src) if n else ""


def _type_simple_name(ty, src):
    """Trailing identifier of a VB `type` node (namespace_name.identifier / generic)."""
    if ty is None:
        return ""
    # walk to the last identifier descendant
    last = None
    stack = [ty]
    while stack:
        x = stack.pop()
        if x.type == "identifier":
            last = x
        stack.extend(reversed(x.children))
    return _t(last, src) if last is not None else _t(ty, src)


def call_parts(node, src):
    callee, recv, args = "", "", []

    if node.type == "new_expression":
        # `New SqlCommand("..." & c)` -> callee is the type name so sinks like
        # SqlCommand / DirectorySearcher / BinaryFormatter / MD5CryptoServiceProvider
        # match; no receiver. args come from the argument_list.
        ty = node.child_by_field_name("type")
        if ty is None:
            for ch in node.named_children:
                if ch.type == "type":
                    ty = ch
                    break
        callee = _type_simple_name(ty, src)
        al = node.child_by_field_name("arguments")
        if al is None:
            for ch in node.children:
                if ch.type == "argument_list":
                    al = ch
                    break
        if al is not None:
            for a in al.named_children:
                args.append(a)
        return callee, "", args

    tgt = node.child_by_field_name("target")
    if tgt is not None:
        if tgt.type == "member_access":
            obj = tgt.child_by_field_name("object")
            mem = tgt.child_by_field_name("member")
            callee = _t(mem, src) if mem else ""
            recv = _t(obj, src) if obj else ""
        else:
            callee = _t(tgt, src)
    al = node.child_by_field_name("arguments")
    if al is not None:
        for a in al.named_children:
            if a.type == "argument":
                args.append(a)
            elif a.type != "":
                args.append(a)
    return callee, recv, args


def assign_parts(node, src):
    names, rhs = [], []
    nm = node.child_by_field_name("name")
    if nm is not None:
        names.append(_t(nm, src))
    else:
        for ch in node.named_children:
            if ch.type == "identifier":
                names.append(_t(ch, src))
                break
    init = node.child_by_field_name("initializer") or node.child_by_field_name("right")
    if init is not None:
        rhs = [init]
    return names, rhs


def return_vals(node):
    return [c for c in node.named_children]
