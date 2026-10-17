#!/usr/bin/env bash
# Bulk-add recon API keys to K1nzr3c0n via the keys API (PUT /api/v1/keys/{provider}).
#
# Secrets are read from an env file (default: scripts/api-keys.env) which is
# GITIGNORED — never put real keys in this script or in the committed example.
#
# Usage:
#   cp scripts/api-keys.env.example scripts/api-keys.env   # then fill in your keys
#   BASE_URL=http://127.0.0.1:8000 ./scripts/add-api-keys.sh
#   # remote server:  BASE_URL=http://192.168.52.103:8000 ./scripts/add-api-keys.sh
#   # with auth token: ARTEX_TOKEN=... ./scripts/add-api-keys.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="${1:-$HERE/api-keys.env}"
BASE_URL="${BASE_URL:-http://127.0.0.1:8000}"

if [ ! -f "$ENV_FILE" ]; then
  echo "error: $ENV_FILE not found — copy api-keys.env.example to api-keys.env and fill it in." >&2
  exit 1
fi
# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a

AUTH=()
[ -n "${ARTEX_TOKEN:-}" ] && AUTH=(-H "Authorization: Bearer ${ARTEX_TOKEN}")

put() { # put <provider_id> <value>
  local id="$1" val="${2:-}"
  if [ -z "$val" ]; then printf '  skip  %-15s (empty)\n' "$id"; return; fi
  local code
  code=$(curl -sS -o /dev/null -w '%{http_code}' -X PUT "$BASE_URL/api/v1/keys/$id" \
    -H 'Content-Type: application/json' "${AUTH[@]}" \
    --data "{\"value\":\"$val\"}" 2>/dev/null || echo 000)
  case "$code" in
    200|201) printf '  ok    %-15s\n' "$id" ;;
    *)       printf '  FAIL  %-15s (HTTP %s)\n' "$id" "$code" ;;
  esac
}

echo "Adding API keys to $BASE_URL ..."
put shodan         "${SHODAN_API_KEY:-}"
put securitytrails "${SECURITYTRAILS_KEY:-}"
put bevigil        "${BEVIGIL_KEY:-}"
put fofa           "${FOFA_KEY:-}"
put chaos          "${CHAOS_API_KEY:-}"
put virustotal     "${VIRUSTOTAL_KEY:-}"
put certspotter    "${CERTSPOTTER_KEY:-}"
put criminalip     "${CRIMINALIP_KEY:-}"
put dnsdumpster    "${DNSDUMPSTER_KEY:-}"
put intelx         "${INTELX_KEY:-}"
put leakix         "${LEAKIX_KEY:-}"
put netlas         "${NETLAS_KEY:-}"
put urlscan        "${URLSCAN_KEY:-}"
put whoisxmlapi    "${WHOISXMLAPI_KEY:-}"
put github         "${GITHUB_TOKEN:-}"
put google_cse     "${GOOGLE_CSE_KEY:-}"
put google_cx      "${GOOGLE_CX:-}"

# Censys stores a single value "API_ID:API_SECRET"
if [ -n "${CENSYS_API_ID:-}" ] && [ -n "${CENSYS_API_SECRET:-}" ]; then
  put censys "${CENSYS_API_ID}:${CENSYS_API_SECRET}"
else
  put censys ""
fi

echo "Done. Check: curl -s $BASE_URL/api/v1/keys/stats  (or the API Keys page)"
