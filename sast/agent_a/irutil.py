"""Shared helpers for walking the extractor IR (used by callgraph + engine)."""


def calls_in_expr(expr):
    """All call nodes inside an expression, recursively (incl. nested args)."""
    if not expr:
        return []
    out = list(expr.get("calls") or [])
    for c in expr.get("calls") or []:
        for a in c.get("args") or []:
            out += calls_in_expr(a)
    return out


def all_calls(op):
    """Every call node reachable from one op (assign rhs / call / return values)."""
    out = []
    if op.get("call"):
        out.append(op["call"])
        for a in op["call"].get("args") or []:
            out += calls_in_expr(a)
    if op.get("rhs"):
        out += calls_in_expr(op["rhs"])
    for e in op.get("values") or []:
        out += calls_in_expr(e)
    return out


def func_calls(func):
    """All call nodes in a function, in op order."""
    out = []
    for op in func.get("ops") or []:
        out += all_calls(op)
    return out


def func_key(func):
    """Canonical key: 'RecvType.Method' for methods, else the function name."""
    rt = (func.get("recvType") or "").lstrip("*")
    if rt:
        return rt + "." + func["name"]
    return func["name"]


def call_key(call):
    """Resolved callee key when the receiver type is known, else None."""
    rt = (call.get("recvType") or "").lstrip("*")
    if rt:
        return rt + "." + call.get("callee", "")
    return None
