#!/bin/bash
# Build the single binary. Rebuilds the frontend too when node is available
# and frontend/ has no node_modules yet.
set -e
cd "$(dirname "$0")"

# NOTE: static/ now holds the prebuilt ScopeWeaver UI (committed in the repo).
# The old k1nzr3c0n React frontend build is intentionally DISABLED so it does not
# overwrite static/. To rebuild the k1nzr3c0n React UI instead, run:
#   (cd frontend && npm run build)   # wipes static/ and replaces it
# To rebuild the ScopeWeaver UI, see K1Z_REBUILD_SWUI below.
if [ "${K1Z_BUILD_FRONTEND:-0}" = "1" ] && command -v npm >/dev/null 2>&1 && [ -d frontend ]; then
  [ -d frontend/node_modules ] || (cd frontend && npm install --no-audit --no-fund)
  echo "[*] building k1nzr3c0n React frontend (overwrites static/)..."
  (cd frontend && npm run build >/dev/null)
fi

echo "[*] building k1nzr3c0n..."
VERSION=${K1Z_VERSION:-$(date +%Y%m%d)-$(git rev-parse --short HEAD 2>/dev/null || echo dev)}
echo "[*] building k1nzr3c0n ($VERSION)..."
go build -ldflags "-X k1nzr3c0n/internal/api.BuildVersion=$VERSION" -o k1nzr3c0n ./cmd/k1nzr3c0n
echo "[+] done: ./k1nzr3c0n"
