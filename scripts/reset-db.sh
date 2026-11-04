#!/usr/bin/env bash
# =============================================================================
# reset-db.sh — wipe and recreate ONLY the artex PostgreSQL database.
#
# What it does (in order):
#   1. (optional) pg_dump backup of the current DB to ~/artex-backup-*.sql.gz
#   2. stop the systemd service so nothing writes mid-reset
#   3. terminate leftover connections, DROP + CREATE DATABASE (owned by the app
#      role) using a SUPERUSER — because the app role often lacks CREATEDB, so
#      the app itself cannot recreate the DB on startup (SQLSTATE 42501)
#   4. grant CREATEDB to the app role so future auto-create works
#   5. start the service and wait until /api/health answers; the app then
#      applies schema.sql + seeds builtins into the fresh empty DB
#   6. (if ARTEX_PASSWORD set) re-initialise the admin password — a DB reset
#      also wipes auth.password_hash, so the app returns to first-run state
#   7. (if ARTEX_PASSWORD set) reseed the Red Team task template
#
# Postgres location is auto-detected: the Docker container (default name
# artex-pg) if present, otherwise a native server reached via sudo -u postgres.
#
# Usage:
#   sudo ARTEX_PASSWORD='yourpass' bash scripts/reset-db.sh            # full reset + reseed
#   sudo ARTEX_PASSWORD='yourpass' bash scripts/reset-db.sh -y         # no confirm prompt
#   sudo bash scripts/reset-db.sh --no-backup                         # skip pg_dump
#   DBNAME=artex SERVICE=k1nzr3c0n-go BASE_URL=http://127.0.0.1:8000 \
#     sudo ARTEX_PASSWORD=... bash scripts/reset-db.sh
#
# Env / flags:
#   ARTEX_PASSWORD   admin password to re-init + login for reseed (skip both if unset)
#   ARTEX_USER       admin username for reseed login (default ARTEX)
#   DBNAME           database + app role name        (default artex)
#   SERVICE          systemd unit                    (default k1nzr3c0n-go)
#   BASE_URL         API base for health/init/reseed (default http://127.0.0.1:8000)
#   PG_CONTAINER     docker postgres container       (default artex-pg)
#   PG_SUPERUSER     superuser role inside postgres  (default = DBNAME, fallback postgres)
#   SRC              source dir holding scripts/      (default /opt/k1nzr3c0n-src, else this repo)
#   -y|--yes         do not prompt for confirmation
#   --no-backup      skip the pg_dump backup
#   --no-service     do not stop/start systemd (you manage the process yourself)
#   --no-reseed      do not reseed the task template
# =============================================================================
set -euo pipefail

DBNAME="${DBNAME:-artex}"
SERVICE="${SERVICE:-k1nzr3c0n-go}"
BASE_URL="${BASE_URL:-http://127.0.0.1:8000}"
PG_CONTAINER="${PG_CONTAINER:-artex-pg}"
PG_SUPERUSER="${PG_SUPERUSER:-}"
ARTEX_USER="${ARTEX_USER:-ARTEX}"
SRC="${SRC:-/opt/k1nzr3c0n-src}"
[ -d "$SRC" ] || SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ASSUME_YES=0; DO_BACKUP=1; DO_SERVICE=1; DO_RESEED=1
while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes)     ASSUME_YES=1; shift ;;
    --no-backup)  DO_BACKUP=0; shift ;;
    --no-service) DO_SERVICE=0; shift ;;
    --no-reseed)  DO_RESEED=0; shift ;;
    -h|--help)    sed -n '2,46p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1 (see -h)" >&2; exit 2 ;;
  esac
done

die()  { echo "ERROR: $*" >&2; exit 1; }
step() { printf '\n==> %s\n' "$*" >&2; }
info() { echo "  $*" >&2; }

# ---- locate postgres: docker container or native --------------------------
PG_MODE="native"
if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$PG_CONTAINER"; then
  PG_MODE="docker"
fi
info "postgres mode: $PG_MODE (db=$DBNAME, service=$SERVICE)"

# psql_super <args...> — run psql as a SUPERUSER against the admin 'postgres' db.
# docker: POSTGRES_USER (default = DBNAME here) is a superuser; fall back to 'postgres'.
# native: use peer auth via 'sudo -u postgres'.
SUPER_TRY=()
if [ -n "$PG_SUPERUSER" ]; then SUPER_TRY=("$PG_SUPERUSER"); else SUPER_TRY=("$DBNAME" "postgres"); fi

psql_super() {
  local u
  if [ "$PG_MODE" = docker ]; then
    for u in "${SUPER_TRY[@]}"; do
      if docker exec -i "$PG_CONTAINER" psql -v ON_ERROR_STOP=1 -U "$u" -d postgres "$@" 2>/tmp/.reset_db_err; then return 0; fi
    done
    cat /tmp/.reset_db_err >&2; return 1
  else
    sudo -u postgres psql -v ON_ERROR_STOP=1 -d postgres "$@"
  fi
}

# ---- confirm --------------------------------------------------------------
if [ "$ASSUME_YES" != 1 ]; then
  echo "This will PERMANENTLY DELETE every row in database '$DBNAME'" >&2
  echo "(tasks, findings, assets, traffic, LLM records, templates, agents, admin password)." >&2
  read -r -p "Type the database name '$DBNAME' to confirm: " ans
  [ "$ans" = "$DBNAME" ] || die "confirmation mismatch — aborted"
fi

# ---- 1. backup ------------------------------------------------------------
if [ "$DO_BACKUP" = 1 ]; then
  step "Backup database -> \$HOME"
  OUT="${HOME:-/root}/artex-backup-$(date +%F-%H%M%S).sql.gz"
  if [ "$PG_MODE" = docker ]; then
    if docker exec -i "$PG_CONTAINER" pg_dump -U "$DBNAME" "$DBNAME" 2>/dev/null | gzip > "$OUT"; then
      info "saved $OUT ($(du -h "$OUT" | cut -f1))"
    else
      rm -f "$OUT"; info "backup skipped (pg_dump failed — DB may already be gone)"
    fi
  else
    if sudo -u postgres pg_dump "$DBNAME" 2>/dev/null | gzip > "$OUT"; then
      info "saved $OUT ($(du -h "$OUT" | cut -f1))"
    else
      rm -f "$OUT"; info "backup skipped (pg_dump failed — DB may already be gone)"
    fi
  fi
fi

# ---- 2. stop service ------------------------------------------------------
if [ "$DO_SERVICE" = 1 ]; then
  step "Stop $SERVICE"
  systemctl stop "$SERVICE" 2>/dev/null || info "systemctl stop failed/absent — continuing"
  sleep 1
fi

# ---- 3. drop + recreate DB (as superuser, owned by app role) --------------
step "Drop + recreate database '$DBNAME'"
psql_super -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='$DBNAME' AND pid<>pg_backend_pid();" >/dev/null || true
psql_super -c "DROP DATABASE IF EXISTS \"$DBNAME\";" || die "DROP DATABASE failed (no superuser access?). Set PG_SUPERUSER or run with a role that can drop '$DBNAME'."
# Ensure the owning role exists, then create the DB owned by it.
if psql_super -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DBNAME';" | grep -qx 1; then
  psql_super -c "CREATE DATABASE \"$DBNAME\" OWNER \"$DBNAME\";" || die "CREATE DATABASE failed"
  psql_super -c "ALTER ROLE \"$DBNAME\" CREATEDB;" >/dev/null 2>&1 \
    && info "granted CREATEDB to role '$DBNAME' (future auto-create works)" \
    || info "note: could not grant CREATEDB to '$DBNAME' (non-fatal)"
else
  psql_super -c "CREATE DATABASE \"$DBNAME\";" || die "CREATE DATABASE failed"
  info "role '$DBNAME' not found — created DB without explicit owner"
fi
info "database recreated empty"

# ---- 4. start service + wait for health -----------------------------------
if [ "$DO_SERVICE" = 1 ]; then
  step "Start $SERVICE and wait for API"
  systemctl reset-failed "$SERVICE" 2>/dev/null || true
  systemctl start "$SERVICE" || die "systemctl start failed — journalctl -u $SERVICE -n 50"
  ok=0
  for _ in $(seq 1 60); do
    code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/api/health" 2>/dev/null || echo 000)
    case "$code" in 200|204) ok=1; break ;; esac
    systemctl is-active "$SERVICE" >/dev/null 2>&1 || die "$SERVICE not active — journalctl -u $SERVICE -n 50"
    sleep 1
  done
  [ "$ok" = 1 ] || die "API did not become healthy — journalctl -u $SERVICE -n 50"
  info "service active; schema applied + builtins seeded"
fi

# ---- 5. re-init admin password (first-run after reset) --------------------
if [ -n "${ARTEX_PASSWORD:-}" ]; then
  step "Re-initialise admin password"
  body=$(P="$ARTEX_PASSWORD" python3 -c 'import json,os;print(json.dumps({"password":os.environ["P"]}))')
  resp=$(curl -sS -X POST "$BASE_URL/api/auth/init" -H 'Content-Type: application/json' --data "$body" 2>/dev/null || true)
  case "$resp" in
    *'"token"'*)              info "admin password set" ;;
    *'already set'*)          info "password already set — skipping (login still works)" ;;
    *)                        info "init response: ${resp:-<empty>} (set it via /setup if login fails)" ;;
  esac
else
  info "ARTEX_PASSWORD unset — skipping admin re-init (set it in the UI /setup page)"
fi

# ---- 6. reseed the Red Team task template ---------------------------------
if [ "$DO_RESEED" = 1 ] && [ -n "${ARTEX_PASSWORD:-}" ] && [ -f "$SRC/scripts/add-task-templates.sh" ]; then
  step "Reseed task template"
  RESEED=1 BASE_URL="$BASE_URL" ARTEX_USER="$ARTEX_USER" ARTEX_PASSWORD="$ARTEX_PASSWORD" \
    bash "$SRC/scripts/add-task-templates.sh" || info "reseed failed (run it manually)"
else
  [ "$DO_RESEED" = 1 ] && info "reseed skipped (need ARTEX_PASSWORD + $SRC/scripts/add-task-templates.sh)"
fi

step "Done — database '$DBNAME' reset. Hard-refresh the browser (Ctrl+Shift+R) and log in."
