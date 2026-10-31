
#!/usr/bin/env bash
# One-command deploy for K1nzr3c0n. Run from the source checkout on the server.
# It does EVERYTHING in the right order so nothing is forgotten (the usual trap is
# a `go build` without rebuilding the embedded frontend):
#   pull → build FE → embed dist → build backend → sync runtime assets → restart
#   → seed API keys. common.txt is fetched from the project release asset.
#
# Usage:
#   sudo bash scripts/deploy.sh                 # full deploy (FE + backend + assets + keys)
#   SKIP_FE=1 sudo bash scripts/deploy.sh       # backend-only (skip the slow FE build)
#   SKIP_KEYS=1 sudo bash scripts/deploy.sh     # skip API key seeding
#   RESEED=1 ARTEX_PASSWORD='...' sudo -E bash scripts/deploy.sh   # also re-seed the task template
#
# API keys: if scripts/api-keys.env exists (gitignored — cp from api-keys.env.example
# and fill in), it is applied automatically after restart via the open /api/v1/keys API.
#
# Env (override as needed):
#   SRC=/opt/k1nzr3c0n-src   K1NZR3C0N_BASE=/opt/k1nzr3c0n   SERVICE=k1nzr3c0n-go
#   BASE_URL=http://127.0.0.1:8000   COMMON_URL=<common.txt release asset>
set -euo pipefail

SRC="${SRC:-/opt/k1nzr3c0n-src}"
BASE="${K1NZR3C0N_BASE:-/opt/k1nzr3c0n}"
SERVICE="${SERVICE:-k1nzr3c0n-go}"
BASE_URL="${BASE_URL:-http://127.0.0.1:8000}"
SKIP_FE="${SKIP_FE:-0}"
RESEED="${RESEED:-0}"

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

cd "$SRC" || die "source dir not found: $SRC"

step "Pull origin/main"
git fetch origin && git reset --hard origin/main
git log --oneline -1

if [ "$SKIP_FE" != "1" ]; then
  step "Build frontend (web/ → server/webui/dist)"
  ( cd web && npm install && npm run build:static )
  [ -f web/out/index.html ] || die "frontend build produced no web/out/index.html"
  rm -rf server/webui/dist && cp -r web/out server/webui/dist
else
  step "SKIP_FE=1 — reusing existing embedded frontend (server/webui/dist)"
fi

step "Build backend (go build -tags embedui)"
ARTEX_SKIP_FRONTEND=1 go build -tags embedui -o k1nzr3c0n ./cmd/artex
./k1nzr3c0n -h >/dev/null 2>&1 && echo "binary OK"

step "Sync runtime assets into $BASE (scripts, workflows, wordlists, skills)"
mkdir -p "$BASE/scripts" "$BASE/wordlists" "$BASE/skills" "$BASE/workflows"
cp scripts/*.py       "$BASE/scripts/"   2>/dev/null && chmod +x "$BASE/scripts/"*.py 2>/dev/null || true
cp scripts/*.sh       "$BASE/scripts/"   2>/dev/null && chmod +x "$BASE/scripts/"*.sh 2>/dev/null || true  # dns-recon.sh etc.
cp -r workflows/*     "$BASE/workflows/" 2>/dev/null || true
cp wordlists/*        "$BASE/wordlists/" 2>/dev/null || true
# standard SecLists wordlists the workflows expect (copied under the exact names)
SL=/usr/share/seclists
[ -f "$SL/Discovery/DNS/subdomains-top1million-20000.txt" ] && cp "$SL/Discovery/DNS/subdomains-top1million-20000.txt" "$BASE/wordlists/subdomains-top1million-20000.txt"
[ -f "$SL/Discovery/Web-Content/burp-parameter-names.txt" ] && cp "$SL/Discovery/Web-Content/burp-parameter-names.txt" "$BASE/wordlists/params-medium.txt"
# common.txt comes from the project's release asset (pinned copy); SecLists is the offline fallback.
COMMON_URL="${COMMON_URL:-https://github.com/kienzx203/Lab_research_tools_k1nz/releases/download/tools/common.txt}"
if curl -fsSL "$COMMON_URL" -o "$BASE/wordlists/common.txt" && [ -s "$BASE/wordlists/common.txt" ]; then
  echo "  common.txt ← release asset ($(wc -l < "$BASE/wordlists/common.txt") lines)"
elif [ -f "$SL/Discovery/Web-Content/common.txt" ]; then
  cp "$SL/Discovery/Web-Content/common.txt" "$BASE/wordlists/common.txt"
  echo "  common.txt download failed — fell back to SecLists"
else
  echo "  WARNING: could not obtain common.txt (no network + no SecLists)"
fi
# in-git skills: every skill dir with a SKILL.md (own recon/workflow skills + the
# vendored offensive-claude set) + the shared references/ library + attribution.
# Skip the huge third-party corpora (hacktricks / payloads-all-the-things), which
# are deployed once and left as-is.
for d in skills/*/; do
  s=$(basename "$d")
  case "$s" in hacktricks|payloads-all-the-things) continue;; esac
  if [ -f "${d}SKILL.md" ] || [ "$s" = "references" ]; then
    cp -r "$d" "$BASE/skills/"
  fi
done
cp skills/OFFENSIVE-CLAUDE-LICENSE skills/OFFENSIVE-CLAUDE-NOTICE.md "$BASE/skills/" 2>/dev/null || true

step "Restart $SERVICE"
systemctl stop "$SERVICE" 2>/dev/null || true
cp k1nzr3c0n "$BASE/"
systemctl daemon-reload 2>/dev/null || true   # pick up any edited unit file (else systemd runs the stale one)
systemctl reset-failed "$SERVICE" 2>/dev/null || true
systemctl start "$SERVICE"
sleep 2
systemctl is-active "$SERVICE" >/dev/null && echo "✓ $SERVICE active" || die "$SERVICE failed to start — check: journalctl -u $SERVICE -n 50"

# Wait until the HTTP server actually ACCEPTS requests before seeding. systemd
# 'active' only means the process forked, not that it is listening — startup can
# take 10-30s with PostgreSQL + migrations. The old 5s wait raced, so seeding
# failed with "HTTP 000000" / "connection refused".
wait_http_ready() {
  local i
  for i in $(seq 1 60); do
    curl -fsS -o /dev/null "$BASE_URL/api/v1/keys/stats" 2>/dev/null && { echo "  service ready ($BASE_URL)"; return 0; }
    systemctl is-active "$SERVICE" >/dev/null 2>&1 || { echo "  ERROR: $SERVICE is not active — journalctl -u $SERVICE -n 60"; return 1; }
    sleep 1
  done
  echo "  WARNING: $BASE_URL not responding after 60s — check: journalctl -u $SERVICE -n 60"
  return 1
}
wait_http_ready || true

step "Seed recon API keys (scripts/api-keys.env → /api/v1/keys)"
if [ "${SKIP_KEYS:-0}" = "1" ]; then
  echo "  SKIP_KEYS=1 — skipping API key seeding"
elif [ -f scripts/api-keys.env ]; then
  BASE_URL="$BASE_URL" bash scripts/add-api-keys.sh || echo "  (api-keys step failed — non-fatal)"
else
  echo "  no scripts/api-keys.env — skipping."
  echo "  (cp scripts/api-keys.env.example scripts/api-keys.env and fill it in to auto-seed keys on deploy)"
fi

if [ "$RESEED" = "1" ] && [ -n "${ARTEX_PASSWORD:-}" ]; then
  step "Re-seed task template (delete old 'Offensive Security'/'Red Team' + recreate)"
  wait_http_ready || true
  TOKEN=$(curl -sS -X POST "$BASE_URL/api/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"ARTEX\",\"password\":\"${ARTEX_PASSWORD}\"}" \
    | python3 -c 'import json,sys;print(json.load(sys.stdin).get("token",""))' 2>/dev/null || true)
  if [ -n "$TOKEN" ]; then
    for tid in $(curl -sS "$BASE_URL/api/task-templates" -H "Authorization: Bearer $TOKEN" \
        | python3 -c "import json,sys;print('\n'.join(str(t['id']) for t in json.load(sys.stdin).get('templates',[]) if t['name'] in ('Offensive Security','Red Team')))" 2>/dev/null); do
      curl -sS -o /dev/null -X DELETE "$BASE_URL/api/task-templates/$tid" -H "Authorization: Bearer $TOKEN" && echo "deleted template $tid"
    done
    BASE_URL="$BASE_URL" ARTEX_TOKEN="$TOKEN" bash scripts/add-task-templates.sh || true
  else
    echo "  (login failed — skipping re-seed; check ARTEX_PASSWORD)"
  fi
fi

# ── Seed Claude Pro/Max (claude-sub) LLM profiles ────────────────────────────
# Reads the server's own Claude Code login (~/.claude/.credentials.json, i.e.
# /root/.claude/… when the service runs as root) and creates one claude-sub
# profile per supported model (opus-4-8 + the Claude 5 family + sonnet/haiku 4.5),
# activating Opus 4.8. Needs ARTEX_PASSWORD to authenticate; non-fatal. Skip with
# SKIP_CLAUDE_SEED=1. Requires `claude` to be logged in on this host.
if [ "${SKIP_CLAUDE_SEED:-0}" != "1" ] && [ -n "${ARTEX_PASSWORD:-}" ]; then
  step "Seed Claude Pro/Max profiles (/api/llm/claude/seed)"
  wait_http_ready || true
  TOKEN=$(curl -sS -X POST "$BASE_URL/api/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"ARTEX\",\"password\":\"${ARTEX_PASSWORD}\"}" \
    | python3 -c 'import json,sys;print(json.load(sys.stdin).get("token",""))' 2>/dev/null || true)
  if [ -n "$TOKEN" ]; then
    curl -sS -X POST "$BASE_URL/api/llm/claude/seed" -H "Authorization: Bearer $TOKEN" \
      | python3 -c 'import json,sys
d=json.load(sys.stdin)
print("  created: "+", ".join(d.get("created",[])) if d.get("ok") else "  skipped: "+str(d.get("error")))' 2>/dev/null \
      || echo "  (claude seed call failed — non-fatal)"
  else
    echo "  (login failed — skipping claude seed; check ARTEX_PASSWORD)"
  fi
fi

step "Done — hard-refresh the browser (Ctrl+Shift+R)"
echo "If you did NOT pass RESEED=1, re-seed the template manually when it changed."
