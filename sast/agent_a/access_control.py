# -*- coding: utf-8 -*-
"""Non-taint access-control analyzer (BROKEN_ACCESS_CONTROL / IDOR / CSRF-ish).

The taint engine finds data-flow bugs (injection, XSS, SSRF, …). It is structurally
blind to the single biggest real-world class — BROKEN ACCESS CONTROL — because there is
no source→sink: the bug is the ABSENCE of an authorization check on a reachable handler.
This module closes that gap heuristically and framework-aware:

For every route handler it decides four facts from the handler's decorators/annotations
and body text:
  - has_guard        : an authentication/authorization check is present
  - is_sensitive     : the handler performs a state change or returns data (worth protecting)
  - takes_object_id  : an attacker-controlled object identifier enters a lookup
  - has_ownership    : the lookup is scoped to the current principal (ownership check)

and emits CANDIDATES (the agent then verifies, exactly like the taint candidates):
  - MISSING_AUTHZ / BROKEN_ACCESS_CONTROL : sensitive handler with NO guard.
  - IDOR                                  : object id used in a lookup with NO ownership scope.

Heuristic by design (favours recall); every finding is `needs-review` confidence so the
reviewing agent confirms reachability + real impact before reporting.
"""

import os
import re

# Per-language framework markers. Keys are file extensions; a language may host several
# frameworks, so the marker sets are unions (Flask+Django+FastAPI for .py, etc.).
_LANG = {
    "py": {
        # a function is a handler when one of these appears in its decorator lines
        "route": re.compile(r"@(app|bp|blueprint|router|api|[a-z_]+)\.(route|get|post|put|delete|patch|websocket)\b|@(app\.)?route\b|urlpatterns|@require_http_methods|def\s+(get|post|put|delete)\s*\(self"),
        "guard": re.compile(r"@login_required|@require[_a-z]*auth|@jwt_required|@roles?_required|@permission_required|@staff_member_required|@user_passes_test|LoginRequiredMixin|PermissionRequiredMixin|login_required|is_authenticated|current_user|request\.user|session\s*\[|session\.get|abort\s*\(\s*40[13]|@admin_required|has_perm|check_permission|@csrf|verify_jwt|get_jwt_identity|@token_required",re.I),
        "sensitive": re.compile(r"\.execute\(|\.raw\(|\.extra\(|\.save\(|\.delete\(|\.update\(|\.create\(|\.objects\.|cursor\.|session\.add|db\.|INSERT\s|UPDATE\s|DELETE\s|SELECT\s|os\.|subprocess|open\s*\(|send_file|\.filter\(", re.I),
        "id_param": re.compile(r"<\s*(?:int|str|uuid|slug)?\s*:?\s*(\w*id\w*|pk|uuid|slug)\s*>|request\.(args|form|values|GET|POST|json)\s*(\.get\s*\(|\[)\s*['\"]?\w*id|\bpk\b|_id\b"),
        "lookup": re.compile(r"\.get\s*\(|\.query\.get|\.objects\.get|\.filter\(|get_object_or_404|\.find\(|WHERE\s+\w*id", re.I),
        "ownership": re.compile(r"current_user|request\.user|session\[|user_id\s*==|owner|\.filter\([^)]*user|user=request\.user|get_jwt_identity|author\s*==|\.mine\b", re.I),
    },
    "js": {
        "route": re.compile(r"\.(get|post|put|delete|patch|all)\s*\(\s*['\"`]/|router\.(route|use)|@(Get|Post|Put|Delete|Patch)\s*\(|app\.(get|post|put|delete)"),
        "guard": re.compile(r"isAuthenticated|requireAuth|require[_A-Za-z]*Auth|ensureLoggedIn|passport\.authenticate|jwt\.verify|verifyToken|req\.user|req\.session|checkAuth|authorize|@UseGuards|AuthGuard|hasRole|isAdmin|ensureAuth|middleware.*auth", re.I),
        "sensitive": re.compile(r"\.query\(|\.execute\(|\.save\(|\.delete\(|\.update\(|\.create\(|\.findOne|\.find\(|knex|sequelize|prisma|db\.|collection\(|res\.(send|json)|exec\(|readFile|writeFile", re.I),
        "id_param": re.compile(r"req\.params\.\w*[iI]d|req\.(query|body)\.\w*[iI]d|:[a-zA-Z_]*[iI]d\b|params\.id\b"),
        "lookup": re.compile(r"findById|\.findOne|\.find\(|\.get\(|WHERE\s+\w*id|getUserById|\.query\(", re.I),
        "ownership": re.compile(r"req\.user|req\.session|userId\s*===|ownerId|\.owner|where.*userId|req\.user\.id|currentUser", re.I),
    },
    "java": {
        "route": re.compile(r"@(RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)|@Path\b|@(GET|POST|PUT|DELETE)\b"),
        "guard": re.compile(r"@PreAuthorize|@PostAuthorize|@Secured|@RolesAllowed|@RequiresPermissions|@RequiresAuthentication|SecurityContextHolder|isAuthenticated|hasRole|hasAuthority|@Authenticated|getPrincipal|@Admin|checkPermission|@Authorized", re.I),
        "sensitive": re.compile(r"\.execute|\.save\(|\.delete\(|\.update|\.create|repository\.|\.findById|\.findOne|entityManager|jdbcTemplate|createQuery|getResultList|Statement|ResponseEntity|@ResponseBody", re.I),
        "id_param": re.compile(r"@PathVariable|@RequestParam[^)]*\w*[iI]d|\{[a-zA-Z_]*[iI]d\}|Long\s+\w*[iI]d|@PathParam"),
        "lookup": re.compile(r"\.findById|\.getOne|\.findOne|\.getById|findBy|createQuery|repository\.", re.I),
        "ownership": re.compile(r"getPrincipal|getCurrentUser|SecurityContext|\.getUserId|ownerId|principal\.|currentUser|== *userId|getAuthentication", re.I),
    },
    "php": {
        "route": re.compile(r"Route::(get|post|put|delete|patch|any|match)|\$(router|app|route)\w*\s*->\s*(get|post|put|delete)|function\s+\w+\s*\([^)]*Request|public\s+function\s+(index|show|store|update|destroy|edit|create)"),
        "guard": re.compile(r"->middleware\s*\(\s*['\"]auth|Auth::check|Auth::user|auth\(\)|\$this->authorize|Gate::|->can\(|can\s*\(|\$request->user|@auth|policy|hasRole|is_admin|checkPermission|csrf", re.I),
        "sensitive": re.compile(r"->(query|execute|get|first|find|save|delete|update|create|insert)\s*\(|DB::|->table\(|Model::|mysqli|PDO|->prepare|->fetch|echo|return\s+view|->findOrFail", re.I),
        "id_param": re.compile(r"\$request->(input|get|post|query)\s*\(\s*['\"]?\w*id|\{[a-zA-Z_]*id\}|function\s+\w+\s*\([^)]*\$id\b|\$id\b|\$_(GET|POST|REQUEST)\s*\[\s*['\"]?\w*id", re.I),
        "lookup": re.compile(r"::find\(|->find\(|findOrFail|::where\(|->where\(|::get\(|->first\(", re.I),
        "ownership": re.compile(r"Auth::id|auth\(\)->id|\$request->user|->user_id|->owner|where\([^)]*user|current_user|->user\(\)|Auth::user", re.I),
    },
    "rb": {
        "route": re.compile(r"\b(get|post|put|delete|patch|resources?)\s+['\":]|def\s+(index|show|create|update|destroy|edit|new)\b"),
        "guard": re.compile(r"before_action\s*:[a-z_]*authenticate|before_filter\s*:[a-z_]*authenticate|authorize|current_user|signed_in|logged_in|require_login|authenticate_user|pundit|cancan|authorize!|can\?|admin_only|check_permission", re.I),
        "sensitive": re.compile(r"\.save|\.destroy|\.update|\.create|\.find|\.where|\.all\b|\.first|ActiveRecord|\.execute|render|redirect_to|\.delete", re.I),
        "id_param": re.compile(r"params\s*\[\s*:[a-z_]*id|params\[:id\]"),
        "lookup": re.compile(r"\.find\(|\.find_by|\.where\(|\.find_or", re.I),
        "ownership": re.compile(r"current_user|\.user_id|\.owner|where\([^)]*user|current_user\.|scope|\.mine\b|authorize\b", re.I),
    },
    "cs": {
        "route": re.compile(r"\[(HttpGet|HttpPost|HttpPut|HttpDelete|HttpPatch|Route)\b|public\s+(async\s+)?(Task<)?IActionResult|ActionResult"),
        "guard": re.compile(r"\[Authorize|\[Authorize\s*\(|User\.Identity|IsAuthenticated|\[RequireHttps|HttpContext\.User|\.IsInRole|ClaimsPrincipal|\[ValidateAntiForgeryToken|CheckPermission", re.I),
        "sensitive": re.compile(r"\.ExecuteNonQuery|\.ExecuteReader|SqlCommand|_context\.|DbSet|\.SaveChanges|\.Find\(|\.FirstOrDefault|\.Where\(|\.Add\(|\.Remove\(|\.Update\(|return\s+(Ok|Json|View)", re.I),
        "id_param": re.compile(r"\{[a-zA-Z_]*id\}|int\s+\w*[iI]d\b|Guid\s+\w*[iI]d|\[FromRoute\]|\[FromQuery\][^,)]*[iI]d"),
        "lookup": re.compile(r"\.Find\(|\.FindAsync|\.FirstOrDefault|\.SingleOrDefault|\.Where\(|FindById", re.I),
        "ownership": re.compile(r"User\.Identity|HttpContext\.User|\.UserId|ownerId|CurrentUser|GetUserId|== *userId|ClaimsPrincipal", re.I),
    },
    "go": {
        "route": re.compile(r"\.(HandleFunc|GET|POST|PUT|DELETE|PATCH|Handle)\s*\(\s*['\"`]/|mux\.|router\.|func\s+\w+\s*\([^)]*http\.ResponseWriter"),
        "guard": re.compile(r"AuthMiddleware|RequireAuth|r\.Context\(\)\.Value|session\.|jwt\.|VerifyToken|IsAuthenticated|middleware.*[Aa]uth|GetUserFromContext|r\.Header\.Get\(\s*['\"]Authorization|checkAuth", re.I),
        "sensitive": re.compile(r"\.Query\(|\.Exec\(|\.QueryRow|db\.|\.Find\(|\.First\(|\.Where\(|\.Save\(|\.Delete\(|\.Create\(|w\.Write|json\.NewEncoder", re.I),
        "id_param": re.compile(r"mux\.Vars|r\.URL\.Query\(\)\.Get\(\s*['\"]?\w*id|\{[a-zA-Z_]*id\}|r\.FormValue\(\s*['\"]?\w*id|c\.Param\(\s*['\"]?\w*id"),
        "lookup": re.compile(r"\.Find\(|\.First\(|\.Where\(|GetByID|FindByID|\.QueryRow", re.I),
        "ownership": re.compile(r"userID|UserID|r\.Context\(\)\.Value|CurrentUser|\.OwnerID|ownerID|== *userID|GetUserFromContext", re.I),
    },
}
_EXT = {".py": "py", ".js": "js", ".jsx": "js", ".ts": "js", ".tsx": "js", ".mjs": "js",
        ".java": "java", ".kt": "java", ".php": "php", ".rb": "rb", ".cs": "cs", ".go": "go"}

_SENSITIVE_PATH = re.compile(r"admin|delete|remove|update|edit|create|user|account|profile|password|role|perm|setting|config|payment|order|invoice|upload|export|download|api", re.I)


def _read(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read().splitlines()
    except OSError:
        return []


def _func_windows(funcs_in_file, nlines):
    """Yield (name, params, start_line, body_start, body_end) for each function, where
    the decorator/annotation lookback is [start_line, body_start) and body is
    [body_start, body_end]. Lines are 1-based."""
    funcs = sorted(funcs_in_file, key=lambda x: x[0])
    for i, (ln, name, params, key) in enumerate(funcs):
        body_end = (funcs[i + 1][0] - 1) if i + 1 < len(funcs) else nlines
        look = max(1, ln - 8)   # decorators/annotations sit just above the def
        yield name, params, key, look, ln, body_end


def analyze(target, funcs):
    """funcs: list of IR function dicts (need 'pos' and 'name'/'params'). Returns a list
    of finding dicts in the engine's shape."""
    by_file = {}
    for f in funcs:
        pos = f.get("pos") or ""
        if ":" not in pos:
            continue
        parts = pos.rsplit(":", 2)
        path = parts[0]
        try:
            line = int(parts[1])
        except (ValueError, IndexError):
            continue
        key = f.get("key") or f.get("name") or ""
        name = f.get("name") or key.rsplit(".", 1)[-1]
        params = [p.get("name") if isinstance(p, dict) else p for p in (f.get("params") or [])]
        by_file.setdefault(path, []).append((line, name, params, key))

    findings = []
    for path, flist in by_file.items():
        ext = os.path.splitext(path)[1].lower()
        lang = _EXT.get(ext)
        if not lang:
            continue
        cfg = _LANG[lang]
        lines = _read(path)
        if not lines:
            continue
        nlines = len(lines)
        for name, params, key, look, start, end in _func_windows(flist, nlines):
            deco = "\n".join(lines[look - 1:start])          # decorator/annotation lookback
            # body is [start, end] but `end` runs up to just before the NEXT function's def,
            # which includes that next handler's decorators/annotations (they sit above its
            # def). Trim trailing decorator/annotation/blank lines so a guard on the next
            # handler is not mis-attributed to this one.
            body_lines = lines[start - 1:end]
            while body_lines and (not body_lines[-1].strip() or body_lines[-1].lstrip().startswith(("@", "[", "//", "#", "/*", "*"))):
                body_lines.pop()
            body = "\n".join(body_lines)
            whole = deco + "\n" + body
            is_handler = bool(cfg["route"].search(deco) or cfg["route"].search(body[:200]))
            if not is_handler:
                continue
            rel = os.path.relpath(path, target) if target else path
            has_guard = bool(cfg["guard"].search(whole))
            is_sensitive = bool(cfg["sensitive"].search(body)) or bool(_SENSITIVE_PATH.search(name))
            takes_id = bool(cfg["id_param"].search(whole))
            does_lookup = bool(cfg["lookup"].search(body))
            has_owner = bool(cfg["ownership"].search(whole))
            route_sensitive = bool(_SENSITIVE_PATH.search(deco))

            base = {"func": key or name, "pos": "%s:%d" % (path, start), "line": start,
                    "weak_sanitizer": False, "interproc": False, "file": rel}

            # (1) Broken access control: a sensitive, attacker-reachable handler with no guard.
            if not has_guard and (is_sensitive or route_sensitive):
                sev = "high" if (route_sensitive and _is_admin(deco, name)) else "medium"
                findings.append(dict(base, category="BROKEN_ACCESS_CONTROL",
                    sink="handler %s() performs a protected operation" % name,
                    sink_note="no authentication/authorization check found on this %s route; verify it is not reachable unauthenticated" % lang,
                    source="HTTP request to this route (no auth guard)",
                    severity=sev, confidence=0.45))

            # (2) IDOR: object id from the request used in a lookup with no ownership scoping,
            #     even if a login guard exists (authn present, authz-per-object absent).
            if takes_id and does_lookup and not has_owner:
                findings.append(dict(base, category="IDOR",
                    sink="object lookup in %s() keyed by a request-supplied id" % name,
                    sink_note="the looked-up object is not scoped to the current user/owner; a different id may expose another principal's data",
                    source="request-controlled object identifier",
                    severity="high" if has_guard else "medium", confidence=0.4))

    return findings


def _is_admin(deco, name):
    return bool(re.search(r"admin|delete|remove|role|perm|grant|revoke", (deco or "") + " " + (name or ""), re.I))
