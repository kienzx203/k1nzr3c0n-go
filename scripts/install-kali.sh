#!/usr/bin/env bash
# ============================================================================
#  k1nzr3c0n — all-in-one installer for Kali Linux (Debian-based)
# ----------------------------------------------------------------------------
#  Installs every dependency, sets up PostgreSQL, builds the frontend + backend,
#  installs the systemd service, and (optionally) wires the Claude Pro/Max
#  subscription LLM. Idempotent — safe to re-run.
#
#  Usage (as root):
#    sudo REPO_URL=https://github.com/<you>/<repo>.git bash scripts/install-kali.sh
#  or from an existing checkout (clones nothing, builds in place):
#    cd /opt/k1nzr3c0n-src && sudo bash scripts/install-kali.sh
#
#  Override anything via env (defaults shown):
#    SRC=/opt/k1nzr3c0n-src   BASE=/opt/k1nzr3c0n   SERVICE=k1nzr3c0n-go
#    PORT=8000   GO_VERSION=1.26.3
#    PG_USER=artex   PG_PASS=artex   PG_DB=artex
#    ADMIN_USER=ARTEX   ADMIN_PASS=<prompted if unset>
#    SKIP_TOOLS=0   SKIP_CLAUDE=0
# ============================================================================
set -euo pipefail

SRC="${SRC:-/opt/k1nzr3c0n-src}"
BASE="${BASE:-/opt/k1nzr3c0n}"
SERVICE="${SERVICE:-k1nzr3c0n-go}"
PORT="${PORT:-8000}"
GO_VERSION="${GO_VERSION:-1.26.3}"
PG_USER="${PG_USER:-artex}"
PG_PASS="${PG_PASS:-artex}"
PG_DB="${PG_DB:-artex}"
ADMIN_USER="${ADMIN_USER:-ARTEX}"
SKIP_TOOLS="${SKIP_TOOLS:-0}"
SKIP_CLAUDE="${SKIP_CLAUDE:-0}"
BASE_URL="http://127.0.0.1:${PORT}"

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }
die()  { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }
[ "$(id -u)" = "0" ] || die "run as root (sudo)."

# ── 1. System packages ──────────────────────────────────────────────────────
step "APT packages (build tools, PostgreSQL, Node, recon essentials)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
  git curl wget ca-certificates build-essential pkg-config \
  postgresql postgresql-contrib \
  nodejs npm \
  python3 python3-pip jq dnsutils whois \
  nmap masscan seclists 2>/dev/null || apt-get install -y git curl wget build-essential postgresql nodejs npm python3 jq

# ── 2. Go toolchain (from go.dev — apt's is too old; go.mod needs ${GO_VERSION}) ─
step "Go ${GO_VERSION}"
if ! command -v go >/dev/null 2>&1 || ! go version 2>/dev/null | grep -q "go${GO_VERSION%.*}"; then
  ARCH=$(dpkg --print-architecture); case "$ARCH" in amd64) GOARCH=amd64;; arm64) GOARCH=arm64;; *) GOARCH=amd64;; esac
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" -o /tmp/go.tgz
  rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz && rm -f /tmp/go.tgz
  ln -sf /usr/local/go/bin/go /usr/local/bin/go
  ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
fi
go version

# ── 3. Recon tools (ProjectDiscovery + helpers) ─────────────────────────────
if [ "$SKIP_TOOLS" != "1" ]; then
  step "Recon tools (nuclei, httpx, subfinder, dnsx, naabu, katana, ...)"
  export GOBIN=/usr/local/bin
  for pkg in \
    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    github.com/projectdiscovery/httpx/cmd/httpx@latest \
    github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
    github.com/projectdiscovery/katana/cmd/katana@latest \
    github.com/ffuf/ffuf/v2@latest \
    github.com/tomnomnom/assetfinder@latest \
    github.com/tomnomnom/waybackurls@latest \
    github.com/lc/gau/v2/cmd/gau@latest; do
    info "go install $pkg"
    go install "$pkg" 2>/dev/null || info "  (skipped $pkg — install manually if a workflow needs it)"
  done
  nuclei -update-templates 2>/dev/null || true
else
  step "SKIP_TOOLS=1 — skipping recon tool install"
fi

# ── 4. Claude CLI (for the Claude Pro/Max subscription LLM) ─────────────────
if [ "$SKIP_CLAUDE" != "1" ]; then
  step "Claude Code CLI (optional — enables the Claude Pro/Max LLM)"
  if ! command -v claude >/dev/null 2>&1; then
    curl -fsSL https://claude.ai/install.sh | bash 2>/dev/null || \
      info "  could not auto-install claude — install it later, then run: claude  (log in), then re-deploy"
  fi
  command -v claude >/dev/null 2>&1 && info "claude installed — run 'sudo claude' and log in to enable Claude Pro/Max" || true
fi

# ── 5. PostgreSQL role + database ───────────────────────────────────────────
step "PostgreSQL role '${PG_USER}' + database '${PG_DB}'"
systemctl enable --now postgresql
sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${PG_USER}'" | grep -q 1 || \
  sudo -u postgres psql -c "CREATE ROLE ${PG_USER} LOGIN PASSWORD '${PG_PASS}' CREATEDB;"
sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='${PG_DB}'" | grep -q 1 || \
  sudo -u postgres psql -c "CREATE DATABASE ${PG_DB} OWNER ${PG_USER};"
PG_DSN="postgres://${PG_USER}:${PG_PASS}@127.0.0.1:5432/${PG_DB}?sslmode=disable"
info "DSN: ${PG_DSN}"

# ── 6. Source checkout ──────────────────────────────────────────────────────
step "Source at ${SRC}"
if [ -d "$SRC/.git" ]; then
  info "existing checkout — pulling"
  git -C "$SRC" fetch origin && git -C "$SRC" reset --hard origin/main
elif [ -n "${REPO_URL:-}" ]; then
  git clone "$REPO_URL" "$SRC"
elif [ -f "$(dirname "$0")/../go.mod" ]; then
  SRC="$(cd "$(dirname "$0")/.." && pwd)"; info "building from current checkout: ${SRC}"
else
  die "no source: set REPO_URL=... or run from inside the repo."
fi
mkdir -p "$BASE"

# ── 7. systemd service ──────────────────────────────────────────────────────
step "systemd unit ${SERVICE}.service (listen :${PORT})"
cat >/etc/systemd/system/${SERVICE}.service <<UNIT
[Unit]
Description=k1nzr3c0n (ARTEX autonomous pentest + recon workflow runner)
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${BASE}
Environment=ARTEX_PG_DSN=${PG_DSN}
Environment=CLAUDE_CONFIG_DIR=/root/.claude
ExecStart=${BASE}/k1nzr3c0n -addr :${PORT}
Restart=on-failure
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable "$SERVICE"

# ── 8. Build + deploy (backend + runtime assets) ────────────────────────────
# SKIP_FE=1: the compiled frontend is committed (server/webui/dist) and embedded,
# so install never depends on a server-side Next.js build. Rebuild the FE later
# only if you change web/ (then: bash scripts/deploy.sh without SKIP_FE).
step "Build & deploy via scripts/deploy.sh (SKIP_FE=1, using committed frontend)"
SRC="$SRC" K1NZR3C0N_BASE="$BASE" SERVICE="$SERVICE" BASE_URL="$BASE_URL" SKIP_FE=1 \
  bash "$SRC/scripts/deploy.sh"

# ── 9. Initialise the admin password (first run only) ───────────────────────
step "Admin account"
if curl -fsS "$BASE_URL/api/auth/status" 2>/dev/null | grep -q '"initialized":true'; then
  info "admin password already set — skipping."
else
  if [ -z "${ADMIN_PASS:-}" ]; then
    read -rsp "    Set admin password for user '${ADMIN_USER}': " ADMIN_PASS; echo
  fi
  code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/api/auth/init" \
    -H 'Content-Type: application/json' \
    -d "$(ADMIN_USER="$ADMIN_USER" ADMIN_PASS="$ADMIN_PASS" python3 -c 'import json,os;print(json.dumps({"username":os.environ["ADMIN_USER"],"password":os.environ["ADMIN_PASS"]}))')" || echo 000)
  case "$code" in 200|201) info "admin '${ADMIN_USER}' created.";; *) info "auth/init returned HTTP ${code} (may already be set).";; esac
fi

# ── Done ────────────────────────────────────────────────────────────────────
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
cat <<DONE

$(printf '\033[1;32m✓ k1nzr3c0n installed.\033[0m')

  Web UI : http://${IP:-127.0.0.1}:${PORT}/        (login: ${ADMIN_USER})
  Service: systemctl status ${SERVICE}   |   journalctl -u ${SERVICE} -f

  Claude Pro/Max (subscription LLM):
    1) sudo claude            # log in once on THIS host (writes /root/.claude/.credentials.json)
    2) In the UI → LLM → "Claude Pro/Max" → Seed all models   (or Add a model)
       — or re-run deploy with seeding:
         SKIP_FE=1 ARTEX_PASSWORD='<admin-pass>' sudo -E bash ${SRC}/scripts/deploy.sh

  Recon API keys (optional, for passive sources):
    cp ${SRC}/scripts/api-keys.env.example ${SRC}/scripts/api-keys.env   # fill in, then re-deploy

  Full guide: ${SRC}/docs/USAGE.md
DONE
