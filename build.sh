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
go build -o k1nzr3c0n ./cmd/k1nzr3c0n
echo "[+] done: ./k1nzr3c0n"
