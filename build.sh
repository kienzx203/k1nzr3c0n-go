#!/bin/bash
# Build the single binary. Rebuilds the frontend too when node is available
# and frontend/ has no node_modules yet.
set -e
cd "$(dirname "$0")"

if command -v npm >/dev/null 2>&1 && [ -d frontend ]; then
  if [ ! -d frontend/node_modules ]; then
    echo "[*] installing frontend deps..."
    (cd frontend && npm install --no-audit --no-fund)
  fi
  echo "[*] building frontend..."
  (cd frontend && npm run build >/dev/null)
fi

echo "[*] building k1nzr3c0n..."
VERSION=${K1Z_VERSION:-$(date +%Y%m%d)-$(git rev-parse --short HEAD 2>/dev/null || echo dev)}
echo "[*] building k1nzr3c0n ($VERSION)..."
go build -ldflags "-X k1nzr3c0n/internal/api.BuildVersion=$VERSION" -o k1nzr3c0n ./cmd/k1nzr3c0n
echo "[+] done: ./k1nzr3c0n"
