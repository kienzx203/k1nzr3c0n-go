"""Perl plugin for the tree-sitter extractor (tree-sitter `perl` grammar)."""

TS_LANG = "perl"
EXTS = [".pl", ".pm", ".t", ".cgi"]

FUNC_TYPES = {"subroutine_declaration_statement"}
LAMBDA_TYPES = {"anonymous_subroutine_expression"}
CLASS_TYPES = {"package_statement"}
CALL_TYPES = {"function_call_expression", "method_call_expression", "call_expression",
              "command_string",   # `cmd` / qx// backticks = shell execution (cmd injection)
              "eval_expression",  # eval EXPR = string eval (code injection)
              # element reads / readline that denote untrusted-input sources
              # (%ENV, @ARGV, <STDIN>). Surfaced as nullary "source calls" so the
              # engine's source matcher fires even when nested in interpolation.
              "hash_element_expression", "array_element_expression",
              "readline_expression"}

# container variable names that denote external input (perl idioms):
#   %ENV env vars, @ARGV command-line args.  Matched by the registered sources
#   "ENV"/"ARGV" (exact callee) and the ENV\[ / argv regexes (full).
_SRC_CONTAINERS = {"ENV", "ARGV"}
ASSIGN_TYPES = {"assignment_expression"}
RETURN_TYPES = {"return_expression", "return_statement"}
STRING_TYPES = {"string_literal", "interpolated_string_literal", "quoted_string"}
# NOTE: interpolated_string_literal is deliberately NOT an INTERP (concat) type.
# Its interpolated variables are captured as idents during the recursive walk, so
# taint still flows through "... $x ..."; but marking EVERY double-quoted string as
# `concat` wrongly defeats the SQLI bind-parameter gate (a constant query string
# with a tainted bind arg would be flagged). Real `.` concatenation (BINARY_TYPES)
# still sets concat. See cov_ruby_perl.yml perl-sqli.
INTERP_TYPES = set()
BINARY_TYPES = {"binary_expression"}
IDENT_TYPES = {"scalar", "array", "hash", "identifier"}


def _t(n, src):
    return src[n.start_byte:n.end_byte].decode("utf-8", "replace")


def pkg_name(root, src, path):
    for ch in root.children:
        if ch.type == "package_statement":
            for c in ch.named_children:
                if c.type in ("package", "identifier", "bareword"):
                    return _t(c, src)
    import os
    return os.path.splitext(os.path.basename(path))[0]


def is_concat(node, src):
    for ch in node.children:
        if ch.type == "." or _t(ch, src) == ".":
            return True
    return False


def func_name(node, src):
    n = node.child_by_field_name("name")
    return _t(n, src) if n else ""


def func_params(node, src):
    # Perl subs usually read args from @_. A modern signature `sub f($x,$y)` is a
    # `signature`; collect its scalar names when present.
    names = []
    sig = node.child_by_field_name("prototype_or_signature") or node.child_by_field_name("signature")
    if sig is not None:
        for ch in sig.named_children:
            if ch.type == "scalar":
                names.append(_t(ch, src))
    return names


def func_body(node):
    return node.child_by_field_name("body")


def class_name(node, src):
    n = node.child_by_field_name("name")
    return _t(n, src) if n else ""


def call_parts(node, src):
    # `cmd` / qx// backticks = shell execution → callee "shell_exec", tainted arg = string.
    if node.type == "command_string":
        return "shell_exec", "", list(node.named_children)   # content (not self → no recursion)
    # eval EXPR / eval { } → callee "eval"; a tainted string eval is code injection.
    if node.type == "eval_expression":
        args = [c for c in node.named_children]   # the evaluated expression(s)
        return "eval", "", args
    # $ENV{x} / $ARGV[n] element reads → emit as a nullary source call when the
    # container is an external-input variable (%ENV / @ARGV). args=[] (NOT [node])
    # → leaf, no recursion. Other hashes/arrays are not sources → empty callee.
    if node.type in ("hash_element_expression", "array_element_expression"):
        base = node.child_by_field_name("variable")
        if base is None and node.named_children:
            base = node.named_children[0]          # container_variable
        name = ""
        if base is not None:
            vn = base.child_by_field_name("name")  # varname inside container_variable
            name = _t(vn, src) if vn is not None else _t(base, src).lstrip("$@%")
        if name in _SRC_CONTAINERS:
            return name, "", []                    # callee==ENV/ARGV matches the registered source
        return "", "", []
    # <STDIN> / <$fh> readline → source call named after the filehandle (STDIN).
    if node.type == "readline_expression":
        fh = node.named_children[0] if node.named_children else None
        name = _t(fh, src) if fh is not None else "STDIN"
        return name, "", []
    callee, recv, args = "", "", []
    if node.type == "method_call_expression":
        inv = node.child_by_field_name("invocant")
        meth = node.child_by_field_name("method")
        recv = _t(inv, src) if inv else ""
        callee = _t(meth, src) if meth else ""
    else:
        fn = node.child_by_field_name("function")
        callee = _t(fn, src) if fn else ""
    namefield = {node.child_by_field_name("function"), node.child_by_field_name("method"),
                 node.child_by_field_name("invocant")}
    for ch in node.named_children:
        if ch in namefield:
            continue
        # call arguments parse as ONE `list_expression` child; unwrap it so each
        # argument is a SEPARATE arg node. Required for per-argument taint logic —
        # e.g. the SQLI bind-parameter gate ($dbh->do("q=?", undef, $tainted) is
        # parameterized/safe) only works when arg[0] (the query) is distinct.
        if ch.type == "list_expression":
            args.extend(ch.named_children)
        else:
            args.append(ch)
    return callee, recv, args


def assign_parts(node, src):
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    names = []
    if left is not None:
        stack = [left]
        while stack:
            x = stack.pop()
            if x.type in ("scalar", "array", "hash"):
                names.append(_t(x, src))
            elif x.type in ("variable_declaration", "parenthesized_expression",
                            "list_expression"):
                stack.extend(x.children)
    rhs = [right] if right is not None else []
    return names, rhs


def return_vals(node):
    return [c for c in node.named_children]
