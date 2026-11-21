"""PHP plugin for the tree-sitter extractor.

Maps the tree-sitter-php grammar's node types to the roles the generic driver
(extract.py) expects. Modeled on plugins/python.py.

PHP-specific points (see extract.py for how each name is used):
  * String concatenation is ``.`` (not ``+``) -> is_concat looks for a ``.``
    operator token inside a binary_expression.
  * Double-quoted/heredoc strings interpolate variables ("... $x ...") -> those
    node types are in INTERP_TYPES so an interpolated string counts as concat.
  * Superglobals ($_GET, $_POST, ...) are array accesses, not calls. We add
    subscript_expression to CALL_TYPES and, in call_parts, surface a superglobal
    base as callee="$_GET" (etc.) so the call-based source matcher sees it.
  * PHP variables carry a leading ``$``; we keep it on every identifier /
    param / lhs name so taint vars line up consistently across the IR.
"""

TS_LANG = "php"
EXTS = [".php"]

FUNC_TYPES = {"function_definition", "method_declaration"}
LAMBDA_TYPES = {"anonymous_function", "arrow_function"}
CLASS_TYPES = {"class_declaration", "trait_declaration",
               "interface_declaration", "enum_declaration"}
# subscript_expression is here so $_GET["x"] style superglobal reads are seen
# by the (call-based) source matcher; call_parts filters out ordinary indexing.
CALL_TYPES = {"function_call_expression", "member_call_expression",
              "nullsafe_member_call_expression", "scoped_call_expression",
              "object_creation_expression", "subscript_expression",
              # include/require are language constructs (not calls) in the PHP grammar;
              # include them so a tainted path → include/require is caught as LFI/RFI.
              "include_expression", "include_once_expression",
              "require_expression", "require_once_expression",
              # echo/print are language constructs too — capture them so a tainted value
              # reaching echo/print is caught as reflected XSS.
              "echo_statement", "print_intrinsic",
              # `cmd` backticks = shell execution (command injection).
              "shell_command_expression"}
_INCLUDE_TYPES = ("include_expression", "include_once_expression",
                  "require_expression", "require_once_expression")
_OUTPUT_TYPES = ("echo_statement", "print_intrinsic")
ASSIGN_TYPES = {"assignment_expression", "augmented_assignment_expression"}
RETURN_TYPES = {"return_statement"}
STRING_TYPES = {"string", "encapsed_string", "heredoc", "nowdoc"}
# Interpolating strings (double-quoted / heredoc) embed variables, i.e. the
# value is a concatenation of literal parts and tainted expressions.
INTERP_TYPES = {"encapsed_string", "heredoc"}
BINARY_TYPES = {"binary_expression"}
IDENT_TYPES = {"variable_name"}

# Superglobals whose array elements are untrusted input.
SUPERGLOBALS = {"$_GET", "$_POST", "$_REQUEST", "$_COOKIE",
                "$_SERVER", "$_FILES", "$_ENV"}


def _t(n, src):
    return src[n.start_byte:n.end_byte].decode("utf-8", "replace")


def pkg_name(root, src, path):
    import os
    return os.path.splitext(os.path.basename(path))[0]


def is_concat(node, src):
    # PHP string concatenation uses the '.' operator (not '+').
    for ch in node.children:
        if ch.type == "." or (not ch.is_named and _t(ch, src) == "."):
            return True
    return False


def func_name(node, src):
    n = node.child_by_field_name("name")
    return _t(n, src) if n else ""


def _param_var(param):
    """The variable_name node of a formal parameter, or None."""
    if param.type == "variable_name":
        return param
    for ch in param.children:
        if ch.type == "variable_name":
            return ch
    return None


def func_params(node, src):
    p = node.child_by_field_name("parameters")
    names = []
    if not p:
        return names
    for ch in p.named_children:
        if ch.type in ("simple_parameter", "variadic_parameter",
                       "property_promotion_parameter", "variable_name"):
            v = _param_var(ch)
            if v is not None:
                names.append(_t(v, src))
    # keep the leading '$' so params line up with variable idents in bodies
    return [n for n in names if n and n != "$this"]


def func_body(node):
    # arrow_function's body is a single expression; others a compound_statement.
    return node.child_by_field_name("body")


def class_name(node, src):
    n = node.child_by_field_name("name")
    return _t(n, src) if n else ""


MEMBER_TYPES = {"member_access_expression", "nullsafe_member_access_expression"}


def member_path(node, src):
    """Dotted field path for a member access: $this->a->b -> '$this.a.b'.
    Enables field-sensitivity (distinct fields = distinct taint keys)."""
    obj = node.child_by_field_name("object")
    name = node.child_by_field_name("name")
    prop = _t(name, src) if name is not None else ""
    if obj is None or not prop:
        return None
    if obj.type in MEMBER_TYPES:
        base = member_path(obj, src)
    elif obj.type == "variable_name":
        base = _t(obj, src)
    else:
        base = _base_var(obj, src)
    return (base + "." + prop) if base else None


def _base_var(node, src):
    """Leftmost variable_name text of an lvalue (subscript/member base)."""
    cur = node
    while cur is not None:
        if cur.type == "variable_name":
            return _t(cur, src)
        nxt = None
        for ch in cur.named_children:
            nxt = ch
            break
        cur = nxt
    return None


def call_parts(node, src):
    """return (callee, recv, [arg_nodes])"""
    t = node.type

    # `cmd` backticks -> callee "shell_exec", content = the tainted command string.
    if t == "shell_command_expression":
        return "shell_exec", "", list(node.named_children)

    # echo/print <expr...>  ->  callee "echo"/"print", args = the output expressions,
    # so a tainted value reaching echo/print is caught as reflected XSS.
    if t in _OUTPUT_TYPES:
        kw = "echo" if t == "echo_statement" else "print"
        return kw, "", [a for a in node.named_children]

    # include/require <path>  ->  callee "include"/"require", arg = the path expr,
    # so an include/require SINK matches and a tainted path → LFI/RFI is reported.
    if t in _INCLUDE_TYPES:
        kw = "include" if t.startswith("include") else "require"
        path = node.named_children[-1] if node.named_children else None
        if path is not None and path.type == "parenthesized_expression":
            inner = [c for c in path.named_children]
            path = inner[0] if inner else path
        return kw, "", ([path] if path is not None else [])

    # Superglobal read: $_GET["x"] -> callee="$_GET" so a source sig matches.
    if t == "subscript_expression":
        base = node.named_children[0] if node.named_children else None
        if base is not None and base.type == "variable_name":
            name = _t(base, src)
            if name in SUPERGLOBALS:
                return name, "", []
        # ordinary array indexing is not a call / source
        return "", "", []

    args_node = node.child_by_field_name("arguments")
    args = list(args_node.named_children) if args_node else []

    if t in ("member_call_expression", "nullsafe_member_call_expression"):
        obj = node.child_by_field_name("object")
        name = node.child_by_field_name("name")
        callee = _t(name, src) if name else ""
        recv = _t(obj, src) if obj else ""     # full object text for sink regexes
        return callee, recv, args

    if t == "scoped_call_expression":
        scope = node.child_by_field_name("scope")
        name = node.child_by_field_name("name")
        callee = _t(name, src) if name else ""
        recv = _t(scope, src) if scope else ""
        return callee, recv, args

    if t == "object_creation_expression":
        # new Foo(...) -> callee = class name (first name/qualified_name child)
        callee = ""
        for ch in node.named_children:
            if ch.type in ("name", "qualified_name", "variable_name"):
                callee = _t(ch, src)
                break
        return callee, "", args

    # function_call_expression: function field is a name / variable_name / etc.
    fn = node.child_by_field_name("function")
    if fn is None:
        return "", "", args
    callee = _t(fn, src)
    # file_get_contents("php://input") / fopen("php://stdin") = reading the raw request
    # body / stdin = untrusted input. Surface a recognizable source callee.
    if callee.lstrip("\\") in ("file_get_contents", "fopen", "stream_get_contents", "fread", "readfile"):
        for a in args:
            if "php://input" in _t(a, src) or "php://stdin" in _t(a, src):
                return "php_input_source", "", args
    # keep full text so e.g. namespaced \mysqli_query or $f() is preserved
    return callee, "", args


def assign_parts(node, src):
    """return (lhs_names, [rhs_nodes])"""
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    names = []
    if left is not None:
        stack = [left]
        while stack:
            x = stack.pop()
            if x.type == "variable_name":
                names.append(_t(x, src))
            elif x.type in MEMBER_TYPES:
                mp = member_path(x, src)   # field-sensitive: $this->a -> '$this.a'
                if mp:
                    names.append(mp)
            elif x.type == "subscript_expression":
                b = _base_var(x, src)      # arrays: taint the base (index-insensitive)
                if b is not None:
                    names.append(b)
            elif x.type in ("list_literal", "array_creation_expression"):
                stack.extend(x.children)   # list(...) destructuring
            # else: ignore (don't descend into index/property expressions)
    rhs = [right] if right is not None else []
    # de-dup, preserve order
    seen, out = set(), []
    for n in names:
        if n and n != "$this" and n not in seen:
            seen.add(n)
            out.append(n)
    return out, rhs


def return_vals(node):
    return [c for c in node.named_children]
