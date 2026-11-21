# -*- coding: utf-8 -*-
"""Framework-aware ENTRY-POINT extractor — the attacker-reachable denominator.

A line-matching route grep misses most of the real surface:
  * convention routing     Rails `resources :x` -> 7 routes, DRF router.register -> CRUD
  * composed paths         Spring @RequestMapping(class) + @GetMapping(method) = /base/x
                           NestJS @Controller('base') + @Get('x'); FastAPI APIRouter(prefix)
  * file-system routing     Next.js pages/api/** , app/**/route.ts  (NO declaration at all)
  * front-controller        index.php?page=x switch-cases
  * non-HTTP entries        GraphQL resolvers, WebSocket, queue consumers, cron jobs, CLI
                           commands, serverless handlers, webhooks

This module expands and composes them so `no endpoint missed` has a denominator that
reflects the real surface. Output (stdout JSON): a list of
  {"kind","method","path","file","line","label"}
kind ∈ http | graphql | websocket | queue | schedule | cli | serverless.

Heuristic + text based (favours recall); every entry is a review obligation the agent
confirms, exactly like the SAST candidates.
"""

import json
import os
import re
import sys

_SKIP_DIRS = {".git", "node_modules", "vendor", ".svn", "dist", "build", "__pycache__",
              ".next", ".venv", "venv", "target", "bin", "obj"}

_CRUD7 = [("GET", "", "index"), ("GET", "/new", "new"), ("POST", "", "create"),
          ("GET", "/{id}", "show"), ("GET", "/{id}/edit", "edit"),
          ("PUT", "/{id}", "update"), ("DELETE", "/{id}", "destroy")]
_CRUD_API = [("GET", "", "list"), ("POST", "", "create"), ("GET", "/{id}", "retrieve"),
             ("PUT", "/{id}", "update"), ("PATCH", "/{id}", "partial_update"),
             ("DELETE", "/{id}", "destroy")]


def _iter_files(root):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in _SKIP_DIRS]
        for fn in fns:
            yield os.path.join(dp, fn)


def _read(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return ""


def _add(out, kind, method, path, file, line, label):
    out.append({"kind": kind, "method": method or "", "path": path or "",
                "file": file, "line": line, "label": (label or (method + " " + path)).strip()})


def _join(prefix, path):
    prefix = (prefix or "").rstrip("/")
    path = path or ""
    if path and not path.startswith("/"):
        path = "/" + path
    return (prefix + path) or "/"


# ───────────────────────────── Python ─────────────────────────────
_PY_DECORATOR = re.compile(r"@(\w+)\.(route|get|post|put|delete|patch|websocket)\s*\(\s*['\"]([^'\"]*)['\"]([^)]*)")
_PY_METHODS = re.compile(r"methods\s*=\s*\[([^\]]*)\]")
_PY_DJ_PATH = re.compile(r"\b(?:re_path|path|url)\s*\(\s*(?:r?['\"])([^'\"]*)['\"]\s*,")
_PY_DRF_REG = re.compile(r"router\.register\s*\(\s*r?['\"]([^'\"]*)['\"]")
_PY_FASTAPI_PREFIX = re.compile(r"APIRouter\s*\([^)]*prefix\s*=\s*['\"]([^'\"]*)['\"]")
_PY_BP_PREFIX = re.compile(r"Blueprint\s*\([^)]*url_prefix\s*=\s*['\"]([^'\"]*)['\"]")
_PY_CLI = re.compile(r"@(?:click|app|cli)\.command|add_parser\s*\(\s*['\"]([^'\"]*)|@app\.command")
_PY_TASK = re.compile(r"@(?:shared_task|celery\.task|app\.task|periodic_task)|@scheduled|schedule\.every")
_PY_LAMBDA = re.compile(r"def\s+(lambda_handler|handler)\s*\(")
_PY_GQL = re.compile(r"@(?:strawberry\.|)(?:query|mutation|field)|def\s+resolve_\w+|class\s+Query\b|class\s+Mutation\b")


def _python(path, text, out):
    prefix = ""
    m = _PY_FASTAPI_PREFIX.search(text) or _PY_BP_PREFIX.search(text)
    if m:
        prefix = m.group(1)
    for i, ln in enumerate(text.splitlines(), 1):
        m = _PY_DECORATOR.search(ln)
        if m:
            verb = m.group(2).upper()
            p = _join(prefix, m.group(3))
            mm = _PY_METHODS.search(m.group(4) or "")
            if verb == "ROUTE" and mm:
                for v in re.findall(r"['\"](\w+)['\"]", mm.group(1)):
                    _add(out, "http", v.upper(), p, path, i, None)
            else:
                _add(out, "http", "" if verb == "ROUTE" else verb, p, path, i, None)
            continue
        m = _PY_DJ_PATH.search(ln)
        if m:
            _add(out, "http", "", "/" + m.group(1).lstrip("^/"), path, i, None)
            continue
        m = _PY_DRF_REG.search(ln)
        if m:
            base = "/" + m.group(1).strip("/")
            for verb, suffix, act in _CRUD_API:
                _add(out, "http", verb, base + suffix, path, i, "%s %s (DRF %s)" % (verb, base + suffix, act))
            continue
        if _PY_GQL.search(ln):
            _add(out, "graphql", "", "", path, i, "GraphQL resolver")
        elif _PY_CLI.search(ln):
            _add(out, "cli", "", "", path, i, "CLI command")
        elif _PY_TASK.search(ln):
            _add(out, "schedule", "", "", path, i, "scheduled/async task")
        elif _PY_LAMBDA.search(ln):
            _add(out, "serverless", "", "", path, i, "serverless handler")


# ───────────────────────────── JS / TS ─────────────────────────────
_JS_ROUTE = re.compile(r"\b(?:app|router|r|api)\.(get|post|put|delete|patch|all|use)\s*\(\s*['\"`]([^'\"`]*)['\"`]")
_NEST_CTRL = re.compile(r"@Controller\s*\(\s*['\"]?([^'\")]*)['\"]?\s*\)")
_NEST_METHOD = re.compile(r"@(Get|Post|Put|Delete|Patch)\s*\(\s*['\"]?([^'\")]*)['\"]?\s*\)?")
_JS_WS = re.compile(r"\.on\s*\(\s*['\"](?!error|close|open)(\w+)['\"]|@SubscribeMessage\s*\(\s*['\"]([^'\"]*)|socket\.on")
_JS_QUEUE = re.compile(r"\.(process|consume|subscribe)\s*\(|@Processor|new Worker\s*\(|\.createConsumer")
_JS_CRON = re.compile(r"cron\.schedule|@Cron\b|new CronJob|setInterval")
_JS_LAMBDA = re.compile(r"exports\.handler\s*=|module\.exports\.handler|export\s+(?:const|async function)\s+handler")
_JS_GQL = re.compile(r"@(Query|Mutation|Resolver)\b|buildSchema|type Query\b|Query:\s*\{|Mutation:\s*\{")


def _js(path, text, out):
    # NestJS: compose @Controller base with method decorators (scan sequentially)
    base = None
    cm = _NEST_CTRL.search(text)
    if cm:
        base = cm.group(1)
    for i, ln in enumerate(text.splitlines(), 1):
        m = _JS_ROUTE.search(ln)
        if m:
            verb = m.group(1).upper()
            if verb == "USE":
                continue  # middleware/prefix mount, not a leaf endpoint
            _add(out, "http", verb, m.group(2) or "/", path, i, None)
            continue
        m = _NEST_METHOD.search(ln)
        if m and base is not None:
            _add(out, "http", m.group(1).upper(), _join(base, m.group(2)), path, i, None)
            continue
        if _JS_GQL.search(ln):
            _add(out, "graphql", "", "", path, i, "GraphQL resolver")
        elif _JS_WS.search(ln):
            _add(out, "websocket", "", "", path, i, "WebSocket handler")
        elif _JS_QUEUE.search(ln):
            _add(out, "queue", "", "", path, i, "queue/worker consumer")
        elif _JS_CRON.search(ln):
            _add(out, "schedule", "", "", path, i, "scheduled job")
        elif _JS_LAMBDA.search(ln):
            _add(out, "serverless", "", "", path, i, "serverless handler")


def _nextjs_fs(root, out):
    """Next.js / SvelteKit file-system routing: the file path IS the route."""
    for path in _iter_files(root):
        rp = path.replace("\\", "/")
        m = re.search(r"/(?:pages|app|src/pages|src/app)/(api/.+?)(?:/route)?\.(?:[jt]sx?)$", rp)
        if m and ("pages/api" in rp or "/route." in rp or "/app/" in rp):
            route = "/" + re.sub(r"/index$", "", m.group(1))
            route = re.sub(r"\[(\.{3})?(\w+)\]", r"{\2}", route)
            _add(out, "http", "", route, path, 1, "Next.js file-route %s" % route)


# ───────────────────────────── Java / Kotlin ─────────────────────────────
# class-level base path: @RequestMapping("/base") sitting on the controller class.
_J_CLASS_RM = re.compile(r"@RequestMapping\s*\(\s*(?:value\s*=\s*)?[\{]?\s*['\"]([^'\"]*)['\"]")
_J_PATH = re.compile(r"@Path\s*\(\s*['\"]([^'\"]*)['\"]\s*\)")
# method mapping: the path, if any, comes ONLY from a quoted string — a bare @PostMapping
# (no args) yields an empty path and must NOT swallow the following `public ...` code.
_J_METHOD = re.compile(r"@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\b(?:\s*\(\s*(?:value\s*=\s*)?[\{]?\s*['\"]([^'\"]*)['\"])?")
_J_KAFKA = re.compile(r"@(KafkaListener|RabbitListener|JmsListener|SqsListener|StreamListener|MessageMapping)\b")
_J_SCHED = re.compile(r"@Scheduled\b|@Cron\b")
_J_GQL = re.compile(r"@(QueryMapping|MutationMapping|SchemaMapping|DgsQuery|DgsMutation)\b")


def _java(path, text, out):
    cm = _J_CLASS_RM.search(text)
    base = cm.group(1) if cm else ""
    base_line = text[:cm.start()].count("\n") + 1 if cm else -1  # skip this line in the loop
    pm = _J_PATH.search(text)
    jaxrs_base = pm.group(1) if pm else ""
    for i, ln in enumerate(text.splitlines(), 1):
        if i == base_line:
            continue  # the class-level @RequestMapping is the base, not an endpoint itself
        m = _J_METHOD.search(ln)
        if m:
            verb = m.group(1).replace("Mapping", "").upper()
            if verb == "REQUEST":
                verb = ""
            _add(out, "http", verb, _join(base, m.group(2) or ""), path, i, None)
            continue
        m = re.search(r"@(GET|POST|PUT|DELETE|PATCH)\b", ln)  # JAX-RS verb on a @Path method
        if m:
            _add(out, "http", m.group(1), _join(jaxrs_base, ""), path, i, None)
            continue
        if _J_KAFKA.search(ln):
            _add(out, "queue", "", "", path, i, "message-queue listener")
        elif _J_SCHED.search(ln):
            _add(out, "schedule", "", "", path, i, "scheduled job")
        elif _J_GQL.search(ln):
            _add(out, "graphql", "", "", path, i, "GraphQL resolver")


# ───────────────────────────── PHP ─────────────────────────────
_PHP_ROUTE = re.compile(r"Route::(get|post|put|delete|patch|any|match)\s*\(\s*['\"]([^'\"]*)")
_PHP_RESOURCE = re.compile(r"Route::(?:apiResource|resource)\s*\(\s*['\"]([^'\"]*)")
_PHP_GROUP = re.compile(r"Route::group\s*\([^)]*['\"]prefix['\"]\s*=>\s*['\"]([^'\"]*)|->prefix\s*\(\s*['\"]([^'\"]*)")
_PHP_SYMFONY = re.compile(r"@Route\s*\(\s*['\"]([^'\"]*)|#\[Route\s*\(\s*['\"]([^'\"]*)")
_PHP_FRONTCTRL = re.compile(r"\$_(?:GET|REQUEST)\s*\[\s*['\"](page|action|cmd|do|module|controller)['\"]\s*\]")


def _php(path, text, out):
    for i, ln in enumerate(text.splitlines(), 1):
        m = _PHP_RESOURCE.search(ln)
        if m:
            base = "/" + m.group(1).strip("/")
            for verb, suffix, act in _CRUD7:
                _add(out, "http", verb, base + suffix, path, i, "%s %s (resource %s)" % (verb, base + suffix, act))
            continue
        m = _PHP_ROUTE.search(ln)
        if m:
            _add(out, "http", m.group(1).upper(), "/" + m.group(2).lstrip("/"), path, i, None)
            continue
        m = _PHP_SYMFONY.search(ln)
        if m:
            _add(out, "http", "", "/" + (m.group(1) or m.group(2) or "").lstrip("/"), path, i, None)
            continue
        if _PHP_FRONTCTRL.search(ln):
            _add(out, "http", "", "?%s=*" % _PHP_FRONTCTRL.search(ln).group(1), path, i,
                 "front-controller dispatch (%s param) — enumerate each case" % _PHP_FRONTCTRL.search(ln).group(1))


# ───────────────────────────── Ruby (Rails) ─────────────────────────────
_RB_RESOURCES = re.compile(r"\bresources?\s+:(\w+)")
_RB_VERB = re.compile(r"\b(get|post|put|patch|delete)\s+['\"]([^'\"]*)")
_RB_NAMESPACE = re.compile(r"\bnamespace\s+:(\w+)")


def _ruby(path, text, out):
    ns = ""
    for i, ln in enumerate(text.splitlines(), 1):
        nm = _RB_NAMESPACE.search(ln)
        if nm:
            ns = "/" + nm.group(1)
        m = _RB_RESOURCES.search(ln)
        if m:
            base = _join(ns, m.group(1))
            singular = ln.strip().startswith("resource ")
            for verb, suffix, act in (_CRUD7 if not singular else [("GET", "", "show"), ("POST", "", "create"), ("PUT", "", "update"), ("DELETE", "", "destroy")]):
                _add(out, "http", verb, base + suffix, path, i, "%s %s (%s)" % (verb, base + suffix, act))
            continue
        m = _RB_VERB.search(ln)
        if m and "resources" not in ln:
            _add(out, "http", m.group(1).upper(), _join(ns, m.group(2)), path, i, None)


# ───────────────────────────── Go ─────────────────────────────
_GO_ROUTE = re.compile(r"\.(GET|POST|PUT|DELETE|PATCH|Handle|HandleFunc)\s*\(\s*['\"`]([^'\"`]*)")
_GO_GROUP = re.compile(r"\.Group\s*\(\s*['\"`]([^'\"`]*)")
_GO_LAMBDA = re.compile(r"lambda\.Start|func\s+HandleRequest")


def _go(path, text, out):
    for i, ln in enumerate(text.splitlines(), 1):
        m = _GO_ROUTE.search(ln)
        if m:
            verb = m.group(1).upper().replace("HANDLEFUNC", "").replace("HANDLE", "")
            _add(out, "http", verb, m.group(2) or "/", path, i, None)
        elif _GO_LAMBDA.search(ln):
            _add(out, "serverless", "", "", path, i, "AWS Lambda handler")


_DISPATCH = {
    ".py": _python, ".js": _js, ".jsx": _js, ".ts": _js, ".tsx": _js, ".mjs": _js,
    ".java": _java, ".kt": _java, ".php": _php, ".rb": _ruby, ".go": _go,
}


def extract(root):
    out = []
    has_next = False
    for path in _iter_files(root):
        ext = os.path.splitext(path)[1].lower()
        fn = _DISPATCH.get(ext)
        if fn:
            try:
                fn(path, _read(path), out)
            except Exception:  # noqa: BLE001 — one bad file never aborts the inventory
                pass
        if ext in (".js", ".jsx", ".ts", ".tsx") and ("/pages/" in path.replace("\\", "/") or "/app/" in path.replace("\\", "/")):
            has_next = True
    if has_next:
        try:
            _nextjs_fs(root, out)
        except Exception:  # noqa: BLE001
            pass
    # de-dup identical (method,path,file,line)
    seen, uniq = set(), []
    for e in out:
        k = (e["kind"], e["method"], e["path"], e["file"], e["line"])
        if k not in seen:
            seen.add(k)
            uniq.append(e)
    return uniq


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    print(json.dumps(extract(target)))
