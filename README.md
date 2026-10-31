<div align="center">

# k1nzr3c0n

**Autonomous offensive-security platform** — an LLM pentest agent fused with a
deterministic recon **workflow runner**, one web UI, one Go binary.

</div>

---

> ⚠️ **Authorized use only.** This is an offensive-security tool. Run it **only**
> against assets you own or have **explicit written permission** to test. You are
> responsible for staying within scope and the law.

---

## What it is

k1nzr3c0n is a fork of **ARTEX** (an autonomous penetration-testing agent) with a
built-in **recon workflow engine**. Two capabilities share one database and UI:

- **🤖 Task Agent (ARTEX core)** — an LLM-driven agent that plans, runs tools,
  records traffic, reproduces and reports findings. It reads your recon data
  (graph, logs, findings) and drives the engagement.
- **⚙️ Workflow Runner (k1z)** — deterministic, resumable recon pipelines
  (subdomains → DNS/ASN → HTTP probing → ports → content/param discovery →
  vuln scan → VHOST matrix). Every tool's output is parsed into the DB **and**
  into a live **relationship graph**.

Both are orchestrated from a Next.js UI and exposed over an HTTP API.

## Key features

| Area | What you get |
| --- | --- |
| **Autonomous agent** | Multi-step task execution, tool use, traffic recording, finding verification + reporting, skills, MCP tool servers. |
| **Recon workflows** | 5 built-in pipelines (`workflows/01…05`), resumable, scope-aware, with a VHOST matrix ("no domain/IP left behind"). |
| **Relationship graph** | Full domain ↔ subdomain ↔ IP ↔ ASN/subnet ↔ port ↔ URL ↔ param ↔ finding ↔ cert/dns/secret/bucket map, per target and per run (graph2 viewer). |
| **Findings & traffic** | Centralised findings store, HTTP traffic recording proxy, tool-execution logs, LLM call recordings. |
| **LLM pool** | Multiple providers (Anthropic, OpenAI, OpenAI-Responses, Ollama) with rotation, failover, circuit breakers and rate limits. |
| **🆕 Claude Pro/Max** | Use your **Claude subscription** as the LLM (no API key) — profiles are created from the server's Claude Code login. See [below](#claude-promax-subscription-llm). |
| **Assets & workspace** | Asset inventory, asset sync, a per-engagement workspace. |
| **Skills** | A large offensive-skills library (AD, cloud, k8s escape, API recon, red-team, AI security, …) the agent can load on demand. |

## Architecture

```
          ┌─────────────────────────── Web UI (Next.js, embedded) ───────────────────────────┐
          │  Dashboard · Chat(agent) · Tasks · Findings · Traffic · Graph · Workflows · LLM   │
          └───────────────────────────────────────┬──────────────────────────────────────────┘
                                                   │  HTTP API (:8000)
          ┌────────────────────────────────────────┴─────────────────────────────────────────┐
          │                          k1nzr3c0n (single Go binary)                              │
          │   agent/  server/  db/      ← ARTEX core (agent, API, PostgreSQL)                  │
          │   k1z/ (runner, graph, api) ← recon workflow engine + relationship graph           │
          │   norma/ (local module)     ← LLM provider layer (Anthropic / OpenAI / claude-sub) │
          └───────────────────────────────────────┬──────────────────────────────────────────┘
                                                   │
                           PostgreSQL  ·  recon tools (nuclei, httpx, subfinder, nmap, …)
```

- **Backend:** Go `1.26+`, module `github.com/Autumn-27/artex`. Build tag
  `embedui` embeds the compiled frontend (`server/webui/dist`).
- **Frontend:** Next.js static export (`web/` → `web/out` → embedded).
- **Database:** PostgreSQL (the app creates the DB if missing; `ARTEX_PG_DSN`).
- **LLM layer:** the vendored local module `./norma`.

## Quick start (Kali)

One command installs everything (Go, Node, PostgreSQL, recon tools, the systemd
service) and builds the app:

```bash
sudo REPO_URL=https://github.com/<you>/<repo>.git bash scripts/install-kali.sh
# …or, from an existing checkout:
cd /opt/k1nzr3c0n-src && sudo bash scripts/install-kali.sh
```

Then open `http://<server-ip>:8000/` and log in as `ARTEX`.
Full walkthrough: **[docs/USAGE.md](docs/USAGE.md)**.

## Claude Pro/Max subscription LLM

You can drive the agent with your **Claude Pro/Max subscription** instead of a
paid API key, by reusing the token the official **Claude Code** CLI already holds
on the server:

1. Install + log in Claude Code on the server host: `sudo claude` (writes
   `/root/.claude/.credentials.json`).
2. In the UI → **LLM → "Claude Pro/Max"** → **Seed all models** (creates one
   profile per supported model: Opus 4.8, Opus/Sonnet/Haiku 5.5, …) or **Add a
   model** to add one by hand (e.g. a newly released id).
3. Pick a profile as active. The token is read live from the server's Claude
   Code login and auto-refreshed; adding/seeding also runs automatically on
   deploy (`deploy.sh`, needs `ARTEX_PASSWORD`).

> ⚠️ Using a Claude subscription **outside** Claude Code violates Anthropic's
> terms and can get the account suspended. This is opt-in and operator-accepted.

## Manual build

```bash
# frontend → embedded dist
cd web && npm install && npm run build:static && cd ..
rm -rf server/webui/dist && cp -r web/out server/webui/dist

# backend (embeds the frontend)
ARTEX_SKIP_FRONTEND=1 go build -tags embedui -o k1nzr3c0n ./cmd/artex

# run (PostgreSQL must be reachable via ARTEX_PG_DSN)
ARTEX_PG_DSN='postgres://artex:artex@127.0.0.1:5432/artex?sslmode=disable' \
  ./k1nzr3c0n -addr :8000
```

Redeploying on a server is handled by **`scripts/deploy.sh`** (pull → build FE →
embed → build backend → sync assets → restart → seed keys + Claude profiles).
`SKIP_FE=1` skips the slow frontend rebuild.

## Repository layout

| Path | Purpose |
| --- | --- |
| `cmd/artex/` | binary entrypoint |
| `agent/` `server/` `db/` | ARTEX core: agent loop, HTTP API, PostgreSQL |
| `k1z/` | recon workflow engine, relationship graph, workflow API |
| `norma/` | vendored LLM provider module (Anthropic / OpenAI / `claude-sub`) |
| `web/` | Next.js frontend (static export, embedded into the binary) |
| `workflows/` | recon pipeline definitions (`01…05.yaml`) |
| `skills/` | offensive-skills library the agent loads on demand |
| `scripts/` | `install-kali.sh`, `deploy.sh`, recon helpers |
| `docs/USAGE.md` | detailed operator guide |

## Credits & license

Built on **ARTEX** by the upstream authors ([Autumn-27/ARTEX](https://github.com/Autumn-27/ARTEX)).
The recon workflow engine, relationship graph, Claude Pro/Max integration and
Kali tooling are additions in this fork. Respect the upstream project's license
and all third-party tool/skill licenses bundled here.
