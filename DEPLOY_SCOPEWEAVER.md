# Deploying — ScopeWeaver base (real) + k1nzr3c0n features

The repo now builds the **real ScopeWeaver** (`github.com/Autumn-27/artex`): full
Go backend + embedded Next.js UI. It requires **PostgreSQL**. k1nzr3c0n's own
code is preserved under `_k1zlegacy/` (Go ignores `_`-prefixed dirs) and is being
ported in as added features.

## 1. PostgreSQL (one-time)

```bash
sudo apt-get install -y postgresql
sudo -u postgres psql -c "CREATE USER artex WITH PASSWORD 'CHANGE_ME';"
sudo -u postgres psql -c "CREATE DATABASE artex OWNER artex;"
```

The schema is created/updated automatically on every start (idempotent).

## 2. Config

Create `config.json` next to the binary (copy from `config.example.json`):

```json
{
  "database": { "host": "127.0.0.1", "port": 5432, "user": "artex", "password": "CHANGE_ME", "dbname": "artex", "sslmode": "disable" },
  "skill_dir": "/opt/k1nzr3c0n/skills"
}
```

Or set `ARTEX_PG_DSN=postgres://artex:CHANGE_ME@127.0.0.1:5432/artex?sslmode=disable`.
LLM keys: `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` (or set in the UI).

## 3. Build (server, Go only — no Node needed)

The prebuilt UI is committed in `server/webui/dist`, so a Go-only build works:

```bash
cd /opt/k1nzr3c0n-src
git pull
ARTEX_SKIP_FRONTEND=1 go build -tags embedui -o k1nzr3c0n ./cmd/artex
```

(To rebuild the UI from source instead, you need Node 22+: `bash build.sh`.)

## 4. systemd

Point the service at the new binary + config, keep your port with `-addr`:

```ini
# /etc/systemd/system/k1nzr3c0n-go.service
[Service]
WorkingDirectory=/opt/k1nzr3c0n
ExecStart=/opt/k1nzr3c0n/k1nzr3c0n -addr :8000
Environment=ARTEX_PG_DSN=postgres://artex:CHANGE_ME@127.0.0.1:5432/artex?sslmode=disable
Restart=always
```

```bash
sudo systemctl stop k1nzr3c0n-go
sudo cp /opt/k1nzr3c0n-src/k1nzr3c0n   /opt/k1nzr3c0n/
sudo cp -r /opt/k1nzr3c0n-src/skills   /opt/k1nzr3c0n/
# config.json must exist in /opt/k1nzr3c0n (not copied from src — it's gitignored)
sudo systemctl daemon-reload
sudo systemctl start k1nzr3c0n-go
```

## 5. First visit

Open `http://<host>:8000` → ScopeWeaver's **/setup** page sets the admin
password once, then you log in. (This is ScopeWeaver's real auth.)

---

### Notes
- Default port is `:8787`; use `-addr :8000` to keep yours.
- `static/`, the old k1nzr3c0n React build, is gone — the UI is now ScopeWeaver's
  embedded frontend.
- `_k1zlegacy/` holds k1nzr3c0n's workflow-runner / targets / schedules / inventory
  / tool-version code, being ported into this ScopeWeaver base.
