"""Java plugin for the tree-sitter extractor.

Maps the tree-sitter `java` grammar's node types to the roles the generic driver
(extract.py) expects. Modeled on plugins/python.py — same module-level interface.
"""

TS_LANG = "java"
EXTS = [".java"]

FUNC_TYPES = {"method_declaration", "constructor_declaration",
              "compact_constructor_declaration"}
LAMBDA_TYPES = {"lambda_expression"}
CLASS_TYPES = {"class_declaration", "interface_declaration",
               "enum_declaration", "record_declaration",
               "annotation_type_declaration"}
CALL_TYPES = {"method_invocation", "object_creation_expression"}
# local_variable_declaration wraps 1+ variable_declarator; we emit one assign
# per declarator, so variable_declarator (not the declaration) is the ASSIGN node.
ASSIGN_TYPES = {"assignment_expression", "variable_declarator"}
RETURN_TYPES = {"return_statement"}
STRING_TYPES = {"string_literal"}
INTERP_TYPES = {"string_interpolation", "template_expression"}  # text blocks / newer grammars
BINARY_TYPES = {"binary_expression"}
IDENT_TYPES = {"identifier"}


def _t(n, src):
    return src[n.start_byte:n.end_byte].decode("utf-8", "replace")


MEMBER_TYPES = {"field_access"}


def member_path(node, src):
    """Dotted field path (this.a.b) for field-sensitivity."""
    o = node.child_by_field_name("object")
    fld = node.child_by_field_name("field")
    name = _t(fld, src) if fld is not None else ""
    if o is None or not name:
        return None
    base = member_path(o, src) if o.type == "field_access" else _t(o, src)
    return (base + "." + name) if base else None


def pkg_name(root, src, path):
    # read the `package a.b.c;` declaration if present, else fall back to filename
    for ch in root.children:
        if ch.type == "package_declaration":
            for c in ch.named_children:
                if c.type in ("scoped_identifier", "identifier"):
                    return _t(c, src)
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
    """Parameter names for methods, constructors and lambdas.

    - method/constructor: `formal_parameters` -> `formal_parameter`/`spread_parameter`
      (each has a `name` field)
    - lambda: `formal_parameters`, or `inferred_parameters` -> `identifier`s,
      or a single bare `identifier`
    """
    p = node.child_by_field_name("parameters")
    if p is None:
        return []
    if p.type == "identifier":
        return [_t(p, src)]
    names = []
    for ch in p.named_children:
        if ch.type == "identifier":
            names.append(_t(ch, src))
            continue
        idn = ch.child_by_field_name("name")
        if idn is None:
            for g in ch.children:
                if g.type == "identifier":
                    idn = g
                    break
        if idn is not None:
            names.append(_t(idn, src))
    return names


def func_body(node):
    # method -> `block`, constructor -> `constructor_body`,
    # lambda -> `block` or a bare expression; all via the `body` field.
    return node.child_by_field_name("body")


def class_name(node, src):
    n = node.child_by_field_name("name")
    return _t(n, src) if n else ""


def call_parts(node, src):
    """return (callee, recv, [arg_nodes])"""
    if node.type == "object_creation_expression":
        # `new Foo(args)` -> callee = type name so specs matching ctor sinks work
        t = node.child_by_field_name("type")
        if t is None:
            for c in node.children:
                if c.type in ("type_identifier", "scoped_type_identifier",
                              "generic_type"):
                    t = c
                    break
        callee = _t(t, src) if t else ""
        args_node = node.child_by_field_name("arguments")
        args = list(args_node.named_children) if args_node else []
        return callee, "", args

    # method_invocation: fields object / name / arguments
    name = node.child_by_field_name("name")
    obj = node.child_by_field_name("object")
    args_node = node.child_by_field_name("arguments")
    args = list(args_node.named_children) if args_node else []
    callee = _t(name, src) if name is not None else ""
    # full object text so source/sink regexes (request.getParameter,
    # Runtime.getRuntime, stmt.executeQuery, ...) match recv.callee, and so that
    # `this.m()` keeps a non-empty recv -> resolves to user methods via by-name?
    # (mirrors Python's self.m()). A no-receiver call `m()` gets recv="" and
    # resolves as a plain name; the sink matcher also tries `callee` alone, so a
    # leading `this.` never blocks sink matching.
    recv = _t(obj, src) if obj is not None else ""
    return callee, recv, args


def assign_parts(node, src):
    """return (lhs_names, [rhs_nodes])"""
    if node.type == "variable_declarator":
        # one declarator; only a real flow when it has an initializer `value`
        val = node.child_by_field_name("value")
        if val is None:
            return [], []
        nm = node.child_by_field_name("name")
        lhs = [_t(nm, src)] if nm is not None else []
        return [n for n in lhs if n != "_"], [val]

    # assignment_expression: fields left / right
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    names = []
    if left is not None:
        stack = [left]
        while stack:
            x = stack.pop()
            if x.type == "identifier":
                names.append(_t(x, src))
            elif x.type == "field_access":
                mp = member_path(x, src)      # field-sensitive: this.a -> 'this.a'
                if mp:
                    names.append(mp)
            elif x.type == "array_access":
                o = x.child_by_field_name("array")
                if o is not None and o.type == "identifier":
                    names.append(_t(o, src))
            else:
                stack.extend(x.children)
    rhs = [right] if right is not None else []
    return [n for n in names if n != "_"], rhs


def return_vals(node):
    return [c for c in node.named_children]


# --- for-each support (added for OWASP Benchmark cookie/param loops) ---
FOREACH_TYPES = {"enhanced_for_statement"}


def foreach_parts(node, src):
    """`for (T v : items)` -> (['v'], items_node)."""
    name = node.child_by_field_name("name")
    it = node.child_by_field_name("value")
    vn = [src[name.start_byte:name.end_byte].decode("utf-8", "replace")] if name else []
    return vn, it


_SOURCE_ANNOS = {"RequestParam","PathVariable","RequestBody","RequestHeader","CookieValue","RequestPart","ModelAttribute","MatrixVariable"}


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
