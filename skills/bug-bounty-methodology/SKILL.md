---
name: bug-bounty-methodology
description: Use when hunting on a bug-bounty program (HackerOne/Bugcrowd/etc.) — building a program attack briefing from scope + what other researchers already found, mining disclosed reports for repeatable patterns per asset, prioritizing by payout × likelihood, avoiding duplicates, and writing a triage-ready report. Modeled on the h1-brain workflow.
metadata:
  type: offensive
  phase: recon-to-report
  tools: h1-brain (MCP), HackerOne GraphQL, disclosed_reports.db
---

# Bug Bounty Methodology

Bug bounty is black-box pentest optimized for SIGNAL and PAYOUT, under a public
program's rules. The edge is knowing the program's scope and **what already
worked there** before you touch it. (Modeled on h1-brain, an MCP server that
pulls HackerOne program data + 3,600+ disclosed paid reports into an attack
briefing.)

## 1. Program briefing FIRST (don't start blind)
- Read the policy: **in-scope vs out-of-scope assets**, allowed testing, bounty
  table, and the KNOWN-ISSUES / safe-harbor section. Staying in scope is the whole
  game — out-of-scope = no bounty and possible legal risk.
- Mine **disclosed reports** for this program and its tech stack (via h1-brain's
  `hack(handle)` or the Hacktivity feed): what bug classes paid, on which assets,
  by which technique. Recurrence is a map — the same class often reappears on new
  endpoints.
- Note duplicates risk: a well-known bug on a popular program is likely already
  filed. Favor fresh surface (new subdomains/features) and depth over breadth.

## 2. Recon tuned to the scope
Drive the recon-engine / recon-to-attack skills, but gate EVERYTHING on the
program's scope (wildcard vs specific hosts). New subdomains, recently shipped
features, forgotten/legacy apps, and acquisitions are where undup'd bugs live.
Pin leads; keep a ledger of asset × tested-class.

## 3. Hunt the high-signal classes
Prioritize by payout × likelihood for THIS stack: IDOR/BOLA & broken access
control, auth/session flaws, SSRF, injection, business-logic abuse, subdomain
takeover, exposed secrets/keys, and info disclosure that chains. Route each to the
matching offensive skill (web-pentest, api-recon, cloud-security, …).

## 4. Confirm, then write a triage-friendly report
- `[CONFIRMED]` only with a reproducible, minimal, NON-DESTRUCTIVE PoC
  (finding-discipline). Prove IMPACT, don't just assert it; never pivot
  out-of-scope or exfiltrate real data.
- Report so a triager reproduces it in one read: clear title, affected asset +
  exact request, step-by-step repro, impact, and a suggested fix. (See
  report-writing.) A great PoC beats a long narrative; include the request/response
  evidence.
- Respect disclosure rules — no public write-up until the program allows it.

## Discipline
Program scope + rules of engagement are binding. In-scope only, non-destructive,
no out-of-scope pivots, no data exfiltration — prove impact and stop.
