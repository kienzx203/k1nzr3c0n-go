"""Ruby plugin for the tree-sitter extractor.

Maps the tree-sitter-ruby grammar's node types to the roles consumed by the
generic driver in ../extract.py. Mirrors the python.py reference, adjusted for
Ruby's grammar:

  - methods: ``method`` / ``singleton_method`` (``def self.x``)
  - blocks & lambdas: ``lambda`` (``->(x){...}``), ``block`` (``{ }``),
    ``do_block`` (``do ... end``) -> anonymous functions (closures)
  - classes / modules: ``class`` / ``module``
  - calls: ``call`` plus the paren-less ``command`` / ``command_call`` /
    ``method_call`` shapes (grammar-version dependent; included for safety)
  - assignments: ``assignment`` / ``operator_assignment``
  - string interpolation ``"#{x}"`` -> treated as concatenation (taint-through)
"""

TS_LANG = "ruby"
EXTS = [".rb"]

FUNC_TYPES = {"method", "singleton_method"}
LAMBDA_TYPES = {"lambda", "block", "do_block"}
CLASS_TYPES = {"class", "module"}
# paren-less calls parse as `call` in current tree-sitter-ruby, but older /
# alternate grammars emit command/command_call/method_call -- accept all.
CALL_TYPES = {"call", "command", "command_call", "method_call", "element_reference",
              "subshell"}   # `cmd` backticks = shell execution (command injection)
# Rails/Rack untrusted-input readers accessed by `[]` (params[:x], request[...], ENV[...])
_ELEMREF_SOURCES = {"params", "request", "session", "cookies", "ENV", "env"}
ASSIGN_TYPES = {"assignment", "operator_assignment"}
RETURN_TYPES = {"return"}
STRING_TYPES = {"string", "bare_string", "heredoc_body"}
INTERP_TYPES = {"interpolation"}        # "#{x}" parts -> treat as concat/taint
BINARY_TYPES = {"binary"}
IDENT_TYPES = {"identifier", "constant"}

# param wrapper node types whose inner identifier is the bound name
_PARAM_WRAP = (
    "optional_parameter", "keyword_parameter", "splat_parameter",
    "hash_splat_parameter", "block_parameter", "forward_parameter",
    "destructured_parameter",
)


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
    # methods / singleton_methods expose a "name" field; blocks/lambdas do not
    # -> they fall through to the driver's anonymous-function path.
    n = node.child_by_field_name("name")
    return _t(n, src) if n else ""


def func_params(node, src):
    # "parameters" covers method_parameters / lambda_parameters / block_parameters
    p = node.child_by_field_name("parameters")
    names = []
    if p is None:
        return names
    for ch in p.named_children:
        if ch.type in ("identifier", "constant"):
            names.append(_t(ch, src))
        elif ch.type in _PARAM_WRAP:
            idn = ch.child_by_field_name("name")
            if idn is None:
                for g in ch.children:
                    if g.type in ("identifier", "constant"):
                        idn = g
                        break
            if idn is not None:
                names.append(_t(idn, src))
    return names


def func_body(node):
    b = node.child_by_field_name("body")
    # a lambda's body field is a `block`/`do_block` wrapper whose own "body"
    # holds the statements -- unwrap it so the driver doesn't re-enter the
    # block as a second nested anonymous function.
    if b is not None and b.type in ("block", "do_block"):
        inner = b.child_by_field_name("body")
        if inner is not None:
            return inner
    return b


def class_name(node, src):
    n = node.child_by_field_name("name")
    return _t(n, src) if n else ""


def call_parts(node, src):
    """return (callee, recv, [arg_nodes])

    callee = method name; recv = FULL receiver text when present so
    source/sink regexes like ``conn.exec`` / ``Kernel.system`` / ``obj.query``
    match on the ``recv.callee`` string. Handles both ``call`` (field-based)
    and the paren-less ``command`` / ``command_call`` shapes.
    """
    # `cmd` backticks (subshell) = shell execution → callee "shell_exec" so a
    # command-injection sink matches; the interpolated string is the tainted arg.
    if node.type == "subshell":
        return "shell_exec", "", list(node.named_children)   # content (not self → no recursion)

    # params[:x] / request[...] / ENV[...] element-reference → surface `base[` as callee
    # so the `\bparams\[` style source regex matches; other `[]` reads aren't sources.
    if node.type == "element_reference":
        base = node.named_children[0] if node.named_children else None
        if base is not None and _t(base, src) in _ELEMREF_SOURCES:
            return _t(base, src) + "[", "", []
        return "", "", []
    method = node.child_by_field_name("method")
    recv_node = node.child_by_field_name("receiver")
    args_node = node.child_by_field_name("arguments")

    args = list(args_node.named_children) if args_node is not None else []

    callee = ""
    if method is not None:
        callee = _t(method, src)
    else:
        # fallback for shapes without a "method" field: first identifier/
        # constant child that isn't the receiver is the callee name.
        for ch in node.named_children:
            if ch is recv_node:
                continue
            if ch.type in ("identifier", "constant"):
                callee = _t(ch, src)
                break

    recv = _t(recv_node, src) if recv_node is not None else ""

    # fallback argument collection when there is no explicit arguments field
    if not args and args_node is None:
        for ch in node.named_children:
            if ch is method or ch is recv_node:
                continue
            if ch.type in ("block", "do_block"):
                continue  # block handled via LAMBDA_TYPES descent
            args.append(ch)

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
            if x.type in ("identifier", "constant", "instance_variable",
                          "class_variable", "global_variable"):
                names.append(_t(x, src))
            elif x.type == "call":
                # attribute-style write: obj.attr = ... -> track the receiver
                obj = x.child_by_field_name("receiver")
                if obj is not None and obj.type in ("identifier", "constant"):
                    names.append(_t(obj, src))
            elif x.type == "element_reference":
                obj = x.child_by_field_name("object")
                if obj is None and x.named_children:
                    obj = x.named_children[0]
                if obj is not None and obj.type in ("identifier", "constant"):
                    names.append(_t(obj, src))
            else:
                stack.extend(x.children)
    rhs = [right] if right is not None else []
    return [n for n in names if n != "_"], rhs


def return_vals(node):
    # `return a, b` wraps values in an argument_list child; unwrap it so each
    # returned expression is analysed individually.
    vals = []
    for c in node.named_children:
        if c.type == "argument_list":
            vals.extend(c.named_children)
        else:
            vals.append(c)
    return vals
