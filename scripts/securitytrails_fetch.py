#!/usr/bin/env python3
"""SecurityTrails multi-mode fetcher.

Usage:
  securitytrails_fetch.py <api_key> <domain> [--mode MODE] [--cookie COOKIE]

Modes:
  subdomains  (default) — full subdomain enumeration, one per line on stdout
  records               — current + historical DNS records (NS/MX/A/AAAA/TXT),
                          one "TYPE<TAB>value<TAB>first_seen<TAB>last_seen" per line
  pivot                 — domains sharing the target's NS servers
                          (same infra = same-org candidates). Tries the paid
                          Search API first, falls back to scraping
                          securitytrails.com/list/ns/<ns> with --cookie.

Output: results on stdout, diagnostics on stderr.
NAT resilience: per-IP TLS fallback, curl fallback, retries with delay.
"""
from __future__ import annotations

import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time

HOSTNAME    = "api.securitytrails.com"
WEB_HOST    = "securitytrails.com"
PORT        = 443
RETRIES     = 5
RETRY_DELAY = 8
IP_TIMEOUT  = 8
PIVOT_PAUSE = 2          # polite delay between NS pivot queries


def log(msg: str) -> None:
    sys.stderr.write(f"[securitytrails] {msg}\n")


def _write(path: str, lines: list[str]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for line in lines:
            fh.write(line + "\n")


def _write_json(path: str, obj) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


# Strict hostname shape — dig/nslookup error text (";; communications error…",
# "no servers could be reached") must never leak into NS/MX sets during
# network-flap windows and become bogus pivot selectors.
_HOST_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$"
)


def _routable_ips(hostname: str) -> list[str]:
    try:
        results = socket.getaddrinfo(hostname, PORT, type=socket.SOCK_STREAM)
    except OSError:
        return []
    seen, out = set(), []
    for r in results:
        ip = r[4][0]
        if ip not in seen and not ip.startswith("100."):   # skip CGNAT
            seen.add(ip)
            out.append(ip)
    return out


class _DirectHTTPS:
    """Minimal HTTPS over a chosen IP (SNI/cert keep the real hostname)."""

    def __init__(self, ip: str, hostname: str, timeout: int = IP_TIMEOUT):
        self.ip, self.hostname, self.timeout = ip, hostname, timeout
        self.sock = None

    def request(self, method: str, path: str, headers: dict | None = None,
                body: bytes | None = None):
        raw = socket.create_connection((self.ip, PORT), timeout=self.timeout)
        ctx = ssl.create_default_context()
        self.sock = ctx.wrap_socket(raw, server_hostname=self.hostname)
        req = [f"{method} {path} HTTP/1.1",
               f"Host: {self.hostname}",
               "Connection: close"]
        for k, v in (headers or {}).items():
            req.append(f"{k}: {v}")
        if body is not None:
            req.append(f"Content-Length: {len(body)}")
        self.sock.sendall(("\r\n".join(req) + "\r\n\r\n").encode())
        if body is not None:
            self.sock.sendall(body)

    def read_response(self) -> tuple[int, str]:
        chunks = []
        while True:
            try:
                b = self.sock.recv(65536)
            except socket.timeout:
                break
            if not b:
                break
            chunks.append(b)
        self.sock.close()
        raw = b"".join(chunks)
        head, _, payload = raw.partition(b"\r\n\r\n")
        parts = head.split(b" ", 2)
        if len(parts) < 2:   # empty/mangled response (server cut us off)
            return 0, ""
        try:
            status = int(parts[1])
        except ValueError:
            return 0, ""
        # SecurityTrails answers with Transfer-Encoding: chunked — decode it,
        # otherwise the body is unparseable JSON framed by chunk-size markers.
        head_lower = head.lower()
        if b"transfer-encoding: chunked" in head_lower:
            payload = self._dechunk(payload)
        return status, payload.decode("utf-8", errors="replace")

    @staticmethod
    def _dechunk(data: bytes) -> bytes:
        out, i = [], 0
        while i < len(data):
            j = data.find(b"\r\n", i)
            if j < 0:
                break
            try:
                size = int(data[i:j].split(b";")[0], 16)
            except ValueError:
                break
            if size == 0:
                break
            out.append(data[j + 2:j + 2 + size])
            i = j + 2 + size + 2
        return b"".join(out)


def _http_json(method: str, path: str, api_key: str,
               payload: dict | None = None, host: str = HOSTNAME) -> tuple[int, dict | None]:
    """JSON request with per-IP attempts + curl fallback. Returns (status, json)."""
    body = json.dumps(payload).encode() if payload is not None else None
    headers = {"apikey": api_key, "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"

    for ip in _routable_ips(host):
        try:
            conn = _DirectHTTPS(ip, host)
            conn.request(method, path, headers, body)
            status, text = conn.read_response()
            if status == 200:
                try:
                    return status, json.loads(text)
                except json.JSONDecodeError:
                    continue
            return status, None
        except Exception as exc:
            log(f"{host} via {ip}: {exc}")
            continue

    # curl fallback (system resolver, own retry logic).
    # -w marker is mandatory: without it a 402/403 plan-limit JSON body was
    # misread as "200 with zero results" and the fallback chain never fired.
    marker = "__K1Z_HTTP_STATUS__:"
    cmd = ["curl", "-sS", "--max-time", str(IP_TIMEOUT * 2),
           "-H", f"apikey: {api_key}", "-H", "Accept: application/json",
           "-X", method, "-w", f"\n{marker}%{{http_code}}"]
    if body is not None:
        cmd += ["-H", "Content-Type: application/json", "-d", body]
    cmd.append(f"https://{host}{path}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=IP_TIMEOUT * 3)
        if r.returncode == 0 and r.stdout:
            out = r.stdout
            idx = out.rfind(marker)
            curl_status = 0
            if idx >= 0:
                try:
                    curl_status = int(out[idx + len(marker):].strip())
                except ValueError:
                    curl_status = 0
                out = out[:idx]
            try:
                return curl_status, json.loads(out)
            except json.JSONDecodeError:
                return curl_status, None
    except Exception as exc:
        log(f"curl fallback: {exc}")
    return 0, None


def _nslookup_records(rtype: str, domain: str) -> set[str]:
    """nslookup fallback — works on Windows and minimal Linux boxes without dig."""
    try:
        r = subprocess.run(["nslookup", f"-type={rtype}", domain],
                           capture_output=True, text=True, timeout=15,
                           shell=(os.name == "nt"))
        out = r.stdout
    except Exception:
        return set()
    found: set[str] = set()
    if rtype.upper() == "NS":
        for m in re.finditer(r"nameserver\s*=\s*([a-z0-9.-]+)", out, re.I):
            found.add(m.group(1).rstrip(".").lower())
    elif rtype.upper() == "MX":
        for m in re.finditer(r"mail exchanger\s*=\s*\d+\s+([a-z0-9.-]+)", out, re.I):
            found.add(m.group(1).rstrip(".").lower())
    return found


def _http_json_retry(method: str, path: str, api_key: str,
                     payload: dict | None = None, attempts: int = 3,
                     delay: int = 5) -> tuple[int, dict | None]:
    """Retry wrapper — VMware NAT links flap between dead/alive windows and a
    single-shot request fails at random. Auth errors short-circuit."""
    last: tuple[int, dict | None] = (0, None)
    for i in range(attempts):
        status, data = _http_json(method, path, api_key, payload)
        if status == 200 and data is not None:
            return status, data
        last = (status, data)
        # 4xx (except 429) are permanent client/plan errors — retrying burns
        # minutes on calls that can never succeed (observed: 400 from a wrong
        # endpoint shape wasted 7min of st_intel_retry for nothing).
        if status in (400, 401, 402, 403, 404, 429):
            break
        if i < attempts - 1:
            time.sleep(delay)
    return last


# ── mode: subdomains ──────────────────────────────────────────────────────────

def fetch_subdomains(api_key: str, domain: str) -> list[str]:
    for attempt in range(1, RETRIES + 1):
        status, data = _http_json(
            "GET", f"/v1/domain/{domain}/subdomains?children_only=false&include_inactive=true",
            api_key)
        if status == 200 and data is not None:
            return [f"{s}.{domain}" for s in data.get("subdomains", [])]
        if status in (401, 403):
            log(f"HTTP {status} — check API key")
            return []
        if status == 429:
            log("HTTP 429 — rate limited")
            return []
        if attempt < RETRIES:
            log(f"subdomains attempt {attempt}/{RETRIES} failed, retry in {RETRY_DELAY}s")
            time.sleep(RETRY_DELAY)
    log(f"all {RETRIES} subdomain attempts failed")
    return []


# ── mode: records ─────────────────────────────────────────────────────────────

def fetch_records(api_key: str, domain: str) -> list[str]:
    """Current + historical DNS records, like the web /dns page."""
    out: list[str] = []
    # Record type lives in the PATH per API docs (/dns/a, /dns/ns, …) — the
    # old ?type=A query form returns 400 "history type not supported".
    for rtype in ("ns", "mx", "a", "aaaa", "txt"):
        status, data = _http_json_retry(
            "GET", f"/v1/history/{domain}/dns/{rtype}", api_key)
        if status != 200 or data is None:
            if status in (401, 403):
                log(f"records {rtype}: HTTP {status} — check API key")
                return out
            continue
        for rec in data.get("records", []):
            values = rec.get("values") or []
            for v in values:
                if isinstance(v, dict):
                    val = (v.get("value") or v.get("ip") or v.get("nameserver")
                           or v.get("exchange") or v.get("text") or "")
                    if isinstance(val, list):
                        val = ",".join(map(str, val))
                else:
                    val = str(v)
                first = rec.get("first_seen", "")
                last = rec.get("last_seen", "")
                if val:
                    out.append(f"{rtype.upper()}\t{val}\t{first}\t{last}")
        time.sleep(1)  # stay gentle on quota
    return out


# ── mode: all — remaining API surfaces ───────────────────────────────────────

def fetch_domain_info(api_key: str, domain: str) -> dict | None:
    """GET /v1/domain/{hostname} — current snapshot (DNS values, counts…).
    None = permanent 4xx → callers must not retry."""
    status, data = _http_json_retry("GET", f"/v1/domain/{domain}", api_key)
    if status in (400, 401, 402, 403, 404):
        log(f"domain info: HTTP {status} — permanent error, skipping")
        return None
    return data or {}


def fetch_whois(api_key: str, domain: str) -> dict | None:
    """GET /v1/domain/{hostname}/whois — current WHOIS record.
    None = permanent 4xx → callers must not retry."""
    status, data = _http_json_retry("GET", f"/v1/domain/{domain}/whois", api_key)
    if status in (400, 401, 402, 403, 404):
        log(f"whois: HTTP {status} — permanent error, skipping")
        return None
    return data or {}


def fetch_whois_history(api_key: str, domain: str) -> dict | None:
    """GET /v1/history/{hostname}/whois — every WHOIS change ST has seen.
    None = permanent 4xx → callers must not retry."""
    status, data = _http_json_retry("GET", f"/v1/history/{domain}/whois", api_key)
    if status in (400, 401, 402, 403, 404):
        log(f"whois history: HTTP {status} — permanent error, skipping")
        return None
    return data or {}


def fetch_ssl(api_key: str, domain: str) -> dict | None:
    """GET /v1/domain/{hostname}/ssl — TLS certificates observed for the domain.
    None = permanent 4xx → callers must not retry."""
    status, data = _http_json_retry("GET", f"/v1/domain/{domain}/ssl", api_key)
    if status in (400, 401, 402, 403, 404):
        log(f"ssl: HTTP {status} — permanent error, skipping")
        return None
    return data or {}


def current_ns_set(api_key: str, domain: str) -> list[str]:
    """The target's live NS hostnames — API (retried) → dig → dig @8.8.8.8."""
    status, data = _http_json_retry(
        "GET", f"/v1/domain/{domain}/dns/records?type=NS", api_key)
    if status == 200 and data:
        ns = []
        for rec in data.get("records", []):
            for v in rec.get("values", []):
                val = (v.get("value") if isinstance(v, dict) else str(v) or "").strip().rstrip(".").lower()
                if val and _HOST_RE.match(val):
                    ns.append(val)
        if ns:
            return sorted(set(ns))
    # dig fallbacks — system resolver first, then 8.8.8.8 directly (NAT may
    # blackhole one but not the other)
    for dig_args in (["dig", "+short", "+time=3", "+tries=2", "NS", domain],
                     ["dig", "+short", "+time=3", "+tries=2", "@8.8.8.8", "NS", domain]):
        try:
            r = subprocess.run(dig_args, capture_output=True, text=True, timeout=15)
            found = {
                h for h in (l.strip().rstrip(".").lower() for l in r.stdout.splitlines())
                if _HOST_RE.match(h or "")
            }
            if found:
                return sorted(found)
        except Exception:
            continue
    # last resort: nslookup (Windows / minimal systems without dig)
    found = _nslookup_records("NS", domain)
    return sorted(found)


# ── mode: pivot ───────────────────────────────────────────────────────────────

def _pivot_api_search(api_key: str, filters: dict) -> tuple[list[str] | None, bool]:
    """POST /v1/domains/list — the real Search endpoint (per official docs).

    Body is a FILTER OBJECT: {"filter": {"ns": "ns2.example.com"}} — not the
    DSL query string. Pagination via ?page=N; every page is fetched so deep
    results (e.g. scec.vn on page 30 of 53 for ns2) are never truncated.

    BUGFIX 2026-08-15: the API returns records[].hostname (not "domain"/
    "apex_domain") and meta.total_pages (not "pages") — the old field names
    parsed 0 records per page, so every pivot silently fell back to the
    ~500-row-capped viewdns source and deep domains were lost.
    Returns (domains_or_None_if_plan_lacks_it, got_200).
    """
    domains: list[str] = []
    page = 1
    got_200 = False
    while page <= 1000:   # guard only — loop ends on API's own end-of-data
        status, data = None, None
        for attempt in range(3):   # per-page retry: NAT flaps mid-pagination
            status, data = _http_json(
                "POST", f"/v1/domains/list?apikey={api_key}&page={page}", api_key,
                payload={"filter": filters})
            if status == 200 and data is not None:
                break
            if status in (400, 401, 402, 403, 404):
                break
            time.sleep(5)
        if status in (402, 403):
            return (domains if domains else None), True   # plan limit
        if status != 200 or data is None:
            break   # network error — caller sees got_200=False and retries
        got_200 = True
        recs = []
        for r in data.get("records", []):
            d = (r.get("hostname") or r.get("domain")
                 or r.get("apex_domain") or "").lower()
            if _HOST_RE.match(d):
                recs.append(d)
        domains.extend(recs)
        meta = data.get("meta") or {}
        pages = meta.get("total_pages") or meta.get("max_page") or data.get("pages")
        total = data.get("total") or meta.get("total")
        if not recs:
            break
        if pages is not None and page >= int(pages):
            break
        if total is not None and len(domains) >= int(total):
            break
        page += 1
        if page % 5 == 0:
            log(f"pivot: {filters} — {len(domains)} domains after {page - 1} pages")
        time.sleep(1)   # quota-friendly paging
    return domains, got_200


def fetch_associated(api_key: str, domain: str) -> list[str]:
    """GET /v1/domain/{hostname}/associated — domains ST links to the target
    (shared company/infra intelligence), all pages."""
    out: list[str] = []
    page = 1
    while page <= 100:
        status, data = _http_json(
            "GET", f"/v1/domain/{domain}/associated?apikey={api_key}&page={page}",
            api_key)
        if status != 200 or data is None:
            if page == 1:
                if status in (400, 401, 402, 403, 404):
                    log(f"associated: HTTP {status} — permanent error, skipping")
                    return None
                return None   # network failure — caller may retry
            break
        recs = []
        for r in data.get("records", []):
            h = (r.get("hostname") or r.get("domain") or "").lower()
            if _HOST_RE.match(h):
                recs.append(h)
        out.extend(recs)
        pages = data.get("pages")
        total = data.get("total")
        if not recs:
            break
        if pages is not None and page >= int(pages):
            break
        if total is not None and len(out) >= int(total):
            break
        page += 1
        time.sleep(1)
    return out


def current_mx_set(api_key: str, domain: str) -> list[str]:
    """The target's live MX hostnames — API (retried) → dig fallbacks."""
    status, data = _http_json_retry(
        "GET", f"/v1/domain/{domain}/dns/records?type=MX", api_key)
    if status == 200 and data:
        mx = []
        for rec in data.get("records", []):
            for v in rec.get("values", []):
                # MX values look like "10 mail.example.com."
                val = (v.get("value") if isinstance(v, dict) else str(v) or "").strip()
                parts = val.split()
                host = parts[-1].rstrip(".").lower() if parts else ""
                if host and _HOST_RE.match(host):
                    mx.append(host)
        if mx:
            return sorted(set(mx))
    for dig_args in (["dig", "+short", "+time=3", "+tries=2", "MX", domain],
                     ["dig", "+short", "+time=3", "+tries=2", "@8.8.8.8", "MX", domain]):
        try:
            r = subprocess.run(dig_args, capture_output=True, text=True, timeout=15)
            found = {
                h for h in (
                    l.split()[-1].rstrip(".").lower()
                    for l in r.stdout.splitlines() if l.strip()
                )
                if _HOST_RE.match(h or "")
            }
            if found:
                return sorted(found)
        except Exception:
            continue
    found = _nslookup_records("MX", domain)
    return sorted(found)


def _pivot_hackertarget(value: str) -> list[str]:
    """Reverse-NS/record fallback on a NON-AWS network path.

    Vietnam → AWS us-east routing (SecurityTrails) flaps badly on bad cable
    days; api.hackertarget.com sits elsewhere and often stays reachable.
    Free tier: 50 req/day/IP — used only when the ST attempt comes back empty.
    """
    try:
        r = subprocess.run(
            ["curl", "-sS", "--max-time", "15",
             f"https://api.hackertarget.com/findshareddns/?q={value}"],
            capture_output=True, text=True, timeout=20)
        text = r.stdout.strip()
        if not text or text.lower().startswith(("error", "!")):
            return []
        return sorted({
            l.strip().lower() for l in text.splitlines()
            if _HOST_RE.match(l.strip().lower())
        })
    except Exception as exc:
        log(f"pivot: hackertarget fallback failed: {exc}")
        return []


def _pivot_viewdns(value: str) -> list[str]:
    """Second reverse-NS source (viewdns.info) — merges past hackertarget's
    ~500-row cap. Best effort: free tier sometimes captcha-limits."""
    try:
        r = subprocess.run(
            ["curl", "-sS", "--max-time", "20",
             "-A", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
             f"https://viewdns.info/reversens/?ns={value}"],
            capture_output=True, text=True, timeout=25)
        html = r.stdout
        if not html or "recaptcha" in html.lower() or "limit" in html.lower()[:2000]:
            return []
        found = set()
        for m in re.finditer(r"<td[^>]*>\s*([a-z0-9.-]+\.[a-z]{2,})\s*</td>",
                             html, re.I):
            h = m.group(1).lower().rstrip(".")
            if _HOST_RE.match(h):
                found.add(h)
        return sorted(found)
    except Exception as exc:
        log(f"pivot: viewdns fallback failed: {exc}")
        return []


def _pivot_web_scrape(ns: str, cookie: str) -> list[str]:
    """Scrape securitytrails.com/list/ns/<ns> (needs a logged-in session cookie)."""
    if not cookie:
        return []
    path = f"/list/ns/{ns}"
    try:
        r = subprocess.run(
            ["curl", "-sS", "--max-time", str(IP_TIMEOUT * 2),
             "-H", f"Cookie: {cookie}",
             "-A", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
             f"https://{WEB_HOST}{path}"],
            capture_output=True, text=True, timeout=IP_TIMEOUT * 3)
        html = r.stdout
    except Exception as exc:
        log(f"web scrape {ns}: {exc}")
        return []
    if not html:
        return []

    domains: set[str] = set()
    # Next.js payload + API responses use "apex_domain":"..." fields
    for m in re.finditer(r'"apex_domain"\s*:\s*"([a-z0-9.-]+)"', html):
        domains.add(m.group(1).lower())
    # fallback: hrefs to /domain/<d>
    for m in re.finditer(r'href="/domain/([a-z0-9.-]+)"', html):
        domains.add(m.group(1).lower())
    return sorted(domains)


def fetch_pivot(api_key: str, domain: str, cookie: str,
                types: tuple[str, ...] = ("ns", "mx"),
                include_associated: bool = True) -> list[str]:
    """Domains sharing the target's infrastructure — every NS/MX server pivoted
    through POST /v1/domains/list (all pages), plus ST's own associated-domains
    intelligence. Nothing truncated.
    """
    selectors: list[tuple[str, dict, str | None]] = []   # (label, filter, ns_value)
    if "ns" in types:
        for ns in current_ns_set(api_key, domain):
            selectors.append((f"ns:{ns}", {"ns": ns}, ns))
    if "mx" in types:
        for mx in current_mx_set(api_key, domain):
            selectors.append((f"mx:{mx}", {"mx": mx}, None))

    found: set[str] = set()

    if not selectors:
        log("pivot: no NS/MX records found")
    else:
        log(f"pivot: {len(selectors)} server(s) → "
            + ", ".join(lbl for lbl, _, _ in selectors))

    for label, filters, ns_val in selectors:
        domains: list[str] = []
        got_200 = False
        # Flaky NAT windows kill whole selectors — retry until we actually
        # reach the API (got_200) or exhaust attempts.
        for attempt in range(3):
            domains, got_200 = _pivot_api_search(api_key, filters)
            if domains is None:      # plan limitation
                break
            if got_200:
                break
            log(f"pivot: {label} — network failed (attempt {attempt + 1}/3), retry in 10s")
            time.sleep(10)
        if domains is None:
            if cookie and ns_val:
                log(f"pivot: Search API unavailable — scraping /list/ns/{ns_val}")
                domains = _pivot_web_scrape(ns_val, cookie)
            else:
                log(f"pivot: {label} — Search API needs a paid plan"
                    + ("" if cookie else "; set ST_COOKIE to scrape NS lists"))
                domains = []
        # Empty (dead network window or plan limit) → merge ALL non-AWS
        # reverse-NS sources. Each caps around ~500 rows; the union covers
        # more of the true list (e.g. ST web shows 5k+ for busy NS servers).
        if not domains and ns_val:
            merged: set[str] = set()
            for src_name, src_fn in (("hackertarget", _pivot_hackertarget),
                                     ("viewdns", _pivot_viewdns)):
                log(f"pivot: {label} — trying {src_name}")
                got = src_fn(ns_val)
                log(f"pivot: {label} — {src_name}: {len(got)} domain(s)")
                merged.update(got)
                time.sleep(2)
            domains = sorted(merged)
        for d in domains or []:
            if d != domain.lower():
                found.add(d)
        log(f"pivot: {label} → {len(domains or [])} domain(s)")
        time.sleep(PIVOT_PAUSE)

    if include_associated:
        log("pivot: fetching ST associated domains")
        assoc: list[str] = []
        for attempt in range(3):
            got = fetch_associated(api_key, domain)
            if got is not None:      # None = hard failure; [] = truth (no assoc)
                assoc = got
                break
            time.sleep(10)
        for d in assoc:
            if d != domain.lower():
                found.add(d)
        log(f"pivot: associated → {len(assoc)} domain(s)")

    return sorted(found)


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    args = [a for a in sys.argv[1:]]
    mode = "subdomains"
    cookie = ""
    pivot_types = ("ns", "mx")
    include_associated = True
    out_dir = "."
    positional = []
    i = 0
    while i < len(args):
        if args[i] == "--mode":
            mode = args[i + 1]; i += 2
        elif args[i] == "--cookie":
            cookie = args[i + 1]; i += 2
        elif args[i] == "--pivot-types":
            pivot_types = tuple(
                t.strip().lower() for t in args[i + 1].split(",") if t.strip()
            ); i += 2
        elif args[i] == "--no-associated":
            include_associated = False; i += 1
        elif args[i] == "--out":
            out_dir = args[i + 1]; i += 2
        else:
            positional.append(args[i]); i += 1

    if len(positional) < 2:
        sys.stderr.write("Usage: securitytrails_fetch.py <api_key> <domain> "
                         "[--mode subdomains|records|pivot|all] [--cookie COOKIE] "
                         "[--pivot-types ns,mx] [--no-associated] [--out DIR]\n")
        sys.exit(1)

    api_key, domain = positional[0], positional[1]
    if not api_key:
        log("empty API key — nothing to do")
        sys.exit(0)

    if mode == "all":
        # One-shot: EVERYTHING the ST API exposes for the target.
        #   st_subdomains.txt       all subdomains
        #   st_dns_records.txt      NS/MX/A/AAAA/TXT current + historical
        #   st_domain_info.json     current domain snapshot
        #   st_whois.json           current WHOIS
        #   st_whois_history.json   WHOIS change history
        #   st_ssl.json             observed TLS certificates
        #   st_associated.txt       ST-linked domains (shared company/infra)
        #   st_pivot_domains.txt    domains sharing NS/MX with the target
        os.makedirs(out_dir, exist_ok=True)

        log("all: fetching subdomains")
        subs = sorted(set(fetch_subdomains(api_key, domain)))
        _write(os.path.join(out_dir, "st_subdomains.txt"), subs)

        log("all: fetching DNS records")
        records = fetch_records(api_key, domain)
        _write(os.path.join(out_dir, "st_dns_records.txt"), records)

        log("all: fetching domain info")
        _write_json(os.path.join(out_dir, "st_domain_info.json"),
                    fetch_domain_info(api_key, domain))

        log("all: fetching WHOIS")
        _write_json(os.path.join(out_dir, "st_whois.json"),
                    fetch_whois(api_key, domain))

        log("all: fetching WHOIS history")
        _write_json(os.path.join(out_dir, "st_whois_history.json"),
                    fetch_whois_history(api_key, domain))

        log("all: fetching SSL certificates")
        _write_json(os.path.join(out_dir, "st_ssl.json"),
                    fetch_ssl(api_key, domain))

        log("all: fetching associated domains")
        assoc: list[str] = []
        for attempt in range(3):
            got = fetch_associated(api_key, domain)
            if got is not None:      # None = hard failure; [] = truth (no assoc)
                assoc = got
                break
            time.sleep(10)
        _write(os.path.join(out_dir, "st_associated.txt"),
               sorted({d for d in assoc if d != domain.lower()}))

        log("all: fetching NS/MX pivot")

        summary = [
            f"subdomains: {len(subs)}  → st_subdomains.txt",
            f"dns records: {len(records)}  → st_dns_records.txt",
            f"associated: {len(assoc)}  → st_associated.txt",
            f"domain info / whois / whois history / ssl  → *.json",
        ]
        print("\n".join(summary))
    elif mode == "missing":
        # Top-up mode: re-fetch ONLY empty/absent st_* sections left behind
        # by a --mode all run that hit NAT dead windows part-way. Each section
        # gets 3 attempts with 20s spacing to wait out flapping.
        if not os.path.isdir(out_dir):
            log(f"missing: no such dir: {out_dir}")
            sys.exit(1)

        def _empty(name: str) -> bool:
            p = os.path.join(out_dir, name)
            # <= 3 covers empty files and an empty JSON object "{}" + newline
            return (not os.path.exists(p)) or os.path.getsize(p) <= 3

        fixed: list[str] = []

        def _assoc_filtered():
            got = fetch_associated(api_key, domain)
            if got is None:
                return None
            return [d for d in got if d != domain.lower()]

        text_sections = (
            ("st_subdomains.txt",
             lambda: sorted(set(fetch_subdomains(api_key, domain)))),
            ("st_dns_records.txt",
             lambda: fetch_records(api_key, domain)),
            ("st_associated.txt", _assoc_filtered),
            ("st_pivot_domains.txt",
             lambda: fetch_pivot(api_key, domain, cookie, pivot_types, False)),
        )
        for name, fetcher in text_sections:
            if not _empty(name):
                continue
            for attempt in range(3):
                log(f"missing: fetching {name} (attempt {attempt + 1}/3)")
                data = fetcher()
                if data is None:
                    log(f"missing: {name} — hard API failure, not retrying")
                    break
                if data or name == "st_associated.txt":
                    # [] for associated is a truthful "no associated domains"
                    _write(os.path.join(out_dir, name), data)
                    fixed.append(f"{name}: {len(data)}")
                    break
                time.sleep(20)
        json_sections = (
            ("st_domain_info.json", lambda: fetch_domain_info(api_key, domain)),
            ("st_whois.json", lambda: fetch_whois(api_key, domain)),
            ("st_whois_history.json", lambda: fetch_whois_history(api_key, domain)),
            ("st_ssl.json", lambda: fetch_ssl(api_key, domain)),
        )
        for name, fetcher in json_sections:
            if not _empty(name):
                continue
            for attempt in range(3):
                log(f"missing: fetching {name} (attempt {attempt + 1}/3)")
                data = fetcher()
                if data is None:
                    log(f"missing: {name} — permanent API error, not retrying")
                    break
                if data:
                    _write_json(os.path.join(out_dir, name), data)
                    fixed.append(name)
                    break
                time.sleep(20)
        print("refilled: " + (", ".join(fixed)
                              if fixed else "nothing (all present or still unreachable)"))
    else:
        log(f"unknown mode: {mode}")
        sys.exit(1)


if __name__ == "__main__":
    main()
