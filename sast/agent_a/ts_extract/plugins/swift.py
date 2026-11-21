"""Swift plugin for the tree-sitter extractor.

Maps the tree-sitter-swift grammar's node types to the roles the generic driver
(extract.py) expects. Mirrors the shape of plugins/python.py.

Node types verified by introspection against tree_sitter_language_pack's "swift"
grammar:
  function_declaration        -> FUNC            (name = first simple_identifier)
  lambda_literal              -> LAMBDA / closure (params in lambda_function_type)
  class_declaration           -> CLASS (covers class/struct/enum/extension)
  protocol_declaration        -> CLASS (recvType only; members have no body)
  call_expression             -> CALL
  navigation_expression       -> a.b member access (field target + navigation_suffix)
  property_declaration        -> `let x = e` / `var x = e`  (ASSIGN)
  assignment                  -> `x = e`                    (ASSIGN)
  control_transfer_statement  -> return / throw / break ... (RETURN)
  line_string_literal /
  multi_line_string_literal   -> STRING (interpolation via interpolated_expression)
  interpolated_expression     -> string interpolation `\\(x)` -> concat/taint
  additive_expression         -> `+` (string concatenation)
  simple_identifier           -> IDENT
"""

TS_LANG = "swift"
EXTS = [".swift"]

FUNC_TYPES = {"function_declaration"}
LAMBDA_TYPES = {"lambda_literal"}
CLASS_TYPES = {"class_declaration", "protocol_declaration"}
CALL_TYPES = {"call_expression"}
ASSIGN_TYPES = {"property_declaration", "assignment"}
RETURN_TYPES = {"control_transfer_statement"}
STRING_TYPES = {"line_string_literal", "multi_line_string_literal"}
INTERP_TYPES = {"interpolated_expression"}   # \(expr) inside a string -> concat
BINARY_TYPES = {"additive_expression"}
IDENT_TYPES = {"simple_identifier"}


def _t(n, src):
    return src[n.start_byte:n.end_byte].decode("utf-8", "replace")


def _descend(n):
    """Yield n and all of its descendants (pre-order)."""
    stack = [n]
    while stack:
        x = stack.pop()
        yield x
        stack.extend(reversed(x.children))


def pkg_name(root, src, path):
    import os
    return os.path.splitext(os.path.basename(path))[0]


def is_concat(node, src):
    # a '+' operator inside an additive_expression (string concatenation)
    for ch in node.children:
        if ch.type == "+" or _t(ch, src) == "+":
            return True
    return False


def func_name(node, src):
    # function_declaration carries several 'name' fields (the func name, each
    # param's internal name, the return type); the first direct simple_identifier
    # child is the function's own name.
    n = node.child_by_field_name("name")
    if n is not None and n.type == "simple_identifier":
        return _t(n, src)
    for ch in node.children:
        if ch.type == "simple_identifier":
            return _t(ch, src)
    return ""


def _param_name(param, src):
    """Internal (body-visible) name of a `parameter` node.

    `func f(label name: T)` -> two simple_identifiers before ':', the 2nd is the
    body name; `func f(x: T)` -> one; `_ x: T` -> ['_', 'x'] -> 'x'.
    """
    ids = []
    for g in param.children:
        if g.type == ":":
            break
        if g.type == "simple_identifier":
            ids.append(g)
    if not ids:  # fallback: any simple_identifier
        ids = [g for g in param.children if g.type == "simple_identifier"]
    return _t(ids[-1], src) if ids else ""


def func_params(node, src):
    names = []

    def collect(n):
        for ch in n.children:
            if ch.type == "parameter":
                nm = _param_name(ch, src)
                if nm:
                    names.append(nm)
            elif ch.type == "lambda_parameter":
                for g in ch.children:
                    if g.type == "simple_identifier":
                        names.append(_t(g, src))
                        break
            elif ch.type in ("lambda_function_type",
                             "lambda_function_type_parameters"):
                collect(ch)

    collect(node)
    return [n for n in names if n not in ("_", "self")]


def func_body(node):
    # function_declaration -> field "body" (function_body);
    # lambda_literal has no "body" field, its statements are a direct child.
    b = node.child_by_field_name("body")
    if b is not None:
        return b
    for ch in node.children:
        if ch.type in ("function_body", "statements"):
            return ch
    return None


def class_name(node, src):
    n = node.child_by_field_name("name")
    if n is not None:
        return _t(n, src)
    for ch in node.children:
        if ch.type in ("type_identifier", "user_type"):
            return _t(ch, src)
    return ""


def _call_args(node, src):
    args = []
    for ch in node.children:
        if ch.type == "call_suffix":
            for g in ch.children:
                if g.type == "value_arguments":
                    for va in g.children:
                        if va.type == "value_argument":
                            v = va.child_by_field_name("value")
                            args.append(v if v is not None else va)
    return args


def _is_format_callee(callee):
    """Is `callee` a format-string sink whose format is arg0? (NSLog,
    String(format:)/NSString(format:), ...WithFormat, appendingFormat,
    localizedStringWithFormat). Kept in sync with the swift-format-string rule."""
    if not callee:
        return False
    return (callee == "NSLog" or "(format:)" in callee
            or "WithFormat" in callee or "appendingFormat" in callee)


def _is_const_string(node):
    """True iff `node` is a string literal with NO interpolation `\\(expr)` — i.e. a
    compile-time constant string that cannot carry taint."""
    if node is None or node.type not in STRING_TYPES:
        return False
    for d in _descend(node):
        if d.type in INTERP_TYPES:
            return False
    return True


def _first_arg_label(node, src):
    """Label of the FIRST value_argument, if any (`String(contentsOfFile:x)` ->
    'contentsOfFile'). Swift argument labels are semantically load-bearing: the
    same initializer/callee name denotes different APIs by label
    (`String(format:)` is a format sink, `String(contentsOfFile:)` is a file read,
    `URL(string:)` vs `URL(fileURLWithPath:)`), and the bare callee text alone
    cannot distinguish them. Returns the label string or None."""
    for ch in node.children:
        if ch.type == "call_suffix":
            for g in ch.children:
                if g.type == "value_arguments":
                    for va in g.children:
                        if va.type == "value_argument":
                            nm = va.child_by_field_name("name")
                            return _t(nm, src) if nm is not None else None
    return None


def call_parts(node, src):
    """return (callee, recv, [arg_nodes])

    The call target is the first child of call_expression:
      - navigation_expression (a.b / Process().run): recv = FULL receiver text
        (field "target"), callee = trailing simple_identifier (navigation_suffix
        field "suffix"). extract.py then builds full = recv + "." + callee.
      - simple_identifier (shell / foo): callee = text, recv = "".
    """
    callee, recv = "", ""
    args = _call_args(node, src)
    fn = node.children[0] if node.children else None
    if fn is None:
        return callee, recv, args
    if fn.type == "navigation_expression":
        tgt = fn.child_by_field_name("target")
        recv = _t(tgt, src) if tgt is not None else ""
        suf = fn.child_by_field_name("suffix")   # navigation_suffix
        idn = suf.child_by_field_name("suffix") if suf is not None else None
        if idn is None and suf is not None:       # fallback: trailing identifier
            kids = [k for k in suf.children if k.type == "simple_identifier"]
            idn = kids[-1] if kids else None
        callee = _t(idn, src) if idn is not None else ""
    elif fn.type == "simple_identifier":
        callee = _t(fn, src)
    else:
        # curried / other callee forms: capture full text as callee (recall-first)
        callee = _t(fn, src)
    # Append the FIRST argument label so label-sensitive APIs stay distinguishable
    # (e.g. String(contentsOfFile:) vs String(format:)). Only done when a label is
    # actually present, so plain positional calls (system(c), popen(c,"r"),
    # sqlite3_exec(db,c,...)) keep their bare callee unchanged.
    if callee:
        lbl = _first_arg_label(node, src)
        if lbl:
            callee = "%s(%s:)" % (callee, lbl)
    # Format-string sinks (NSLog / String(format:) / ...(…WithFormat)) are a
    # format-string VULNERABILITY only when the FORMAT argument (arg0) is tainted;
    # the trailing data varargs are substituted safely by %@/%d/etc. The engine
    # fires a sink on ANY tainted arg, so if we left the data args in place a
    # perfectly safe `NSLog("%@", userInput)` would be a false positive. When arg0
    # is a CONSTANT (non-interpolated) string literal the format is safe, so we drop
    # the trailing data varargs; a tainted/interpolated format (arg0) is kept and
    # still reported.
    if args and _is_format_callee(callee) and _is_const_string(args[0]):
        args = args[:1]
    return callee, recv, args


def assign_parts(node, src):
    """return (lhs_names, [rhs_nodes]) for property_declaration and assignment."""
    names, rhs = [], []
    if node.type == "property_declaration":
        # field "name" = pattern (bound_identifier simple_identifier),
        # field "value" = initializer.
        pat = node.child_by_field_name("name")
        if pat is not None:
            bi = pat.child_by_field_name("bound_identifier")
            if bi is not None:
                names.append(_t(bi, src))
            else:
                for g in _descend(pat):
                    if g.type == "simple_identifier":
                        names.append(_t(g, src))
                        break
        val = node.child_by_field_name("value")
        if val is not None:
            rhs.append(val)
    elif node.type == "assignment":
        tgt = node.child_by_field_name("target")
        if tgt is not None:
            for g in _descend(tgt):
                if g.type == "simple_identifier":
                    names.append(_t(g, src))
                    break
        res = node.child_by_field_name("result")
        if res is not None:
            rhs.append(res)
    return [n for n in names if n != "_"], rhs


def return_vals(node):
    # control_transfer_statement: return/throw carry field "result"; the
    # return keyword is anonymous, throw_keyword is named but ident-free.
    r = node.child_by_field_name("result")
    if r is not None:
        return [r]
    return [c for c in node.named_children]
