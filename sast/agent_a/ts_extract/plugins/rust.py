"""Rust plugin for the tree-sitter extractor.

Maps the `tree-sitter-rust` grammar's node types to the roles the generic
driver in extract.py expects. Modelled on plugins/python.py (the reference).

Grammar facts used (verified via tree_sitter_language_pack.get_parser("rust")):
  function_item     fields: name, parameters, body            -> FUNC
  closure_expression fields: parameters, body                 -> LAMBDA
  impl_item (type) / struct_item,trait_item (name)            -> CLASS (methods
                                                                 live in impl_item)
  call_expression   fields: function, arguments               -> CALL
  macro_invocation  fields: macro (ident) + token_tree(args)  -> CALL (format!/println!)
  field_expression  fields: value, field                      -> x.method()
  scoped_identifier fields: path, name                        -> Command::new, a::b::c
  let_declaration   fields: pattern, value   (`let x = e`)    -> ASSIGN
  assignment_expression fields: left, right                   -> ASSIGN
  return_expression                                           -> RETURN
  binary_expression (+)                                       -> concat
  string_literal / raw_string_literal                        -> STRING
  token_tree (macro body)                                     -> INTERP (format/concat)
  identifier / field_identifier                               -> IDENT
"""

TS_LANG = "rust"
EXTS = [".rs"]

FUNC_TYPES = {"function_item"}
LAMBDA_TYPES = {"closure_expression"}
CLASS_TYPES = {"impl_item", "struct_item", "trait_item"}
CALL_TYPES = {"call_expression", "macro_invocation"}
ASSIGN_TYPES = {"let_declaration", "assignment_expression", "compound_assignment_expr"}
RETURN_TYPES = {"return_expression"}
STRING_TYPES = {"string_literal", "raw_string_literal"}
# a macro's token-tree body (format!("{}",x)/println!) is treated as an
# interpolation/concat carrier so string-building taint is flagged.
INTERP_TYPES = {"token_tree"}
BINARY_TYPES = {"binary_expression"}
IDENT_TYPES = {"identifier", "field_identifier"}


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


# ---------------------------------------------------------------- functions

def func_name(node, src):
    n = node.child_by_field_name("name")
    return _t(n, src) if n else ""


def _pattern_idents(node, src, out):
    """Collect identifier names from a (possibly compound) binding pattern,
    ignoring `&`, `mut`, `ref`, types, etc."""
    if node is None:
        return
    if node.type == "identifier":
        out.append(_t(node, src))
        return
    # tuple / struct / ref / mut patterns -> descend to the plain identifiers
    for ch in node.named_children:
        _pattern_idents(ch, src, out)


def func_params(node, src):
    """Params for both `function_item` and `closure_expression` (both expose a
    `parameters` field). Each entry is the pattern identifier; `&`, `mut` and
    types are ignored, and `self` is dropped."""
    p = node.child_by_field_name("parameters")
    names = []
    if p is None:
        return names
    for ch in p.named_children:
        if ch.type == "parameter":
            pat = ch.child_by_field_name("pattern")
            _pattern_idents(pat if pat is not None else ch, src, names)
        elif ch.type == "identifier":            # bare closure param: |z|
            names.append(_t(ch, src))
        elif ch.type == "self_parameter":
            continue
        else:                                    # defensive: other pattern kinds
            _pattern_idents(ch, src, names)
    return [n for n in names if n != "self"]


def func_body(node):
    return node.child_by_field_name("body")


# ------------------------------------------------------------------- classes

def class_name(node, src):
    # struct_item / trait_item use `name`; impl_item uses `type`.
    n = node.child_by_field_name("name") or node.child_by_field_name("type")
    return _t(n, src) if n else ""


# --------------------------------------------------------------------- calls

def call_parts(node, src):
    """return (callee, recv, [arg_nodes])."""
    # format!("{}", x) / println! ... -> macro name is the callee, args in token_tree
    if node.type == "macro_invocation":
        m = node.child_by_field_name("macro")
        callee = _t(m, src) if m else ""
        args = []
        for ch in node.named_children:
            if ch.type == "token_tree":
                args = [a for a in ch.named_children]
                break
        return callee, "", args

    fn = node.child_by_field_name("function")
    args_node = node.child_by_field_name("arguments")
    args = list(args_node.named_children) if args_node else []
    callee, recv = "", ""
    if fn is None:
        return callee, recv, args

    if fn.type == "field_expression":
        # x.method(...)  -> callee = method name, recv = FULL value text
        # (so `Command::new("sh").arg(x)` keeps the whole receiver chain).
        obj = fn.child_by_field_name("value")
        attr = fn.child_by_field_name("field")
        callee = _t(attr, src) if attr else ""
        recv = _t(obj, src) if obj else ""
    elif fn.type == "scoped_identifier":
        # Command::new / std::process::Command::new / libc::system
        # -> callee = last segment, recv = path prefix (so `Command`, `exec`,
        #    `system` match sink/source patterns).
        name = fn.child_by_field_name("name")
        path = fn.child_by_field_name("path")
        callee = _t(name, src) if name else _t(fn, src)
        recv = _t(path, src) if path else ""
    elif fn.type == "identifier":
        callee = _t(fn, src)
    else:
        callee = _t(fn, src)
    return callee, recv, args


# ------------------------------------------------------------------- assigns

def assign_parts(node, src):
    """return (lhs_names, [rhs_nodes])."""
    names = []
    if node.type == "let_declaration":
        pat = node.child_by_field_name("pattern")
        val = node.child_by_field_name("value")
        _pattern_idents(pat, src, names)
        rhs = [val] if val is not None else []
        return [n for n in names if n != "_"], rhs

    # assignment_expression / compound_assignment_expr: left = right
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is not None:
        stack = [left]
        while stack:
            x = stack.pop()
            if x.type == "identifier":
                names.append(_t(x, src))
            elif x.type == "field_expression":
                obj = x.child_by_field_name("value")
                if obj is not None and obj.type == "identifier":
                    names.append(_t(obj, src))
            elif x.type == "index_expression":
                obj = x.child_by_field_name("value") or (
                    x.named_children[0] if x.named_children else None)
                if obj is not None and obj.type == "identifier":
                    names.append(_t(obj, src))
            else:
                stack.extend(x.children)
    rhs = [right] if right is not None else []
    return [n for n in names if n != "_"], rhs


def return_vals(node):
    # `return expr;` -> the returned expression(s); `return;` -> none.
    return [c for c in node.named_children]
