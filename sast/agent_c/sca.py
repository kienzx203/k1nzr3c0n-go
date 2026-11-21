# -*- coding: utf-8 -*-
"""Software Composition Analysis: review dependencies for KNOWN CVEs via OSV.dev.

Real SCA (not model-guessed CVEs): parse the project's dependency manifests/lockfiles,
query the OSV.dev batch API (free, no key, authoritative), and report each vulnerable
package with its CVE/GHSA ids, severity and the fixed version. Only public package
coordinates (ecosystem + name + version) leave the host — never source or user data.

Offline-safe: if OSV cannot be reached, it returns the parsed dependency inventory with a
note so the reviewer can look the versions up manually.

Usage: python3 sca.py <dir>   → JSON {deps:<n>, vulnerable:[...], offline:bool, note:...}
"""

import json
import os
import re
import sys
import urllib.request

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
_SKIP = {".git", "node_modules", "vendor", ".svn", "dist", "build", "__pycache__", ".next", "venv", ".venv", "target"}
_MAX_VULN_DETAIL = 80  # cap per-vuln detail fetches


def _clean_ver(v):
    v = (v or "").strip().strip('"\'')
    v = re.sub(r"^[\^~>=<! ]+", "", v)        # ^1.2.3, >=1.2 → 1.2.3 / 1.2
    v = v.lstrip("v")                          # go's v1.2.3 → 1.2.3 (OSV Go wants the v; re-added below)
    v = v.split(",")[0].split(" ")[0]
    return v.strip()


def _walk(root, names):
    found = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in _SKIP]
        for fn in fns:
            if fn in names or any(fn.endswith(s) for s in names if s.startswith(".")):
                found.append(os.path.join(dp, fn))
    return found


# ── parsers: each returns [(ecosystem, name, version, manifest_rel)] ──
def _parse(root):
    deps = []
    rel = lambda p: os.path.relpath(p, root)

    # npm: lockfile (exact) preferred, else package.json (ranges)
    for p in _walk(root, {"package-lock.json"}):
        try:
            d = json.load(open(p, encoding="utf-8", errors="ignore"))
            pkgs = d.get("packages") or {}
            if pkgs:
                for k, v in pkgs.items():
                    if k.startswith("node_modules/") and v.get("version"):
                        deps.append(("npm", k.split("node_modules/")[-1], v["version"], rel(p)))
            else:
                for n, v in (d.get("dependencies") or {}).items():
                    if isinstance(v, dict) and v.get("version"):
                        deps.append(("npm", n, v["version"], rel(p)))
        except Exception:
            pass
    seen_npm = {(e, n) for e, n, _, _ in deps}
    for p in _walk(root, {"package.json"}):
        try:
            d = json.load(open(p, encoding="utf-8", errors="ignore"))
            for sec in ("dependencies", "devDependencies"):
                for n, v in (d.get(sec) or {}).items():
                    if ("npm", n) not in seen_npm:
                        deps.append(("npm", n, _clean_ver(v), rel(p)))
        except Exception:
            pass

    # PyPI: requirements.txt
    for p in _walk(root, {"requirements.txt"}):
        try:
            for ln in open(p, encoding="utf-8", errors="ignore"):
                m = re.match(r"\s*([A-Za-z0-9_.\-]+)\s*==\s*([0-9][\w.\-]*)", ln)
                if m:
                    deps.append(("PyPI", m.group(1), m.group(2), rel(p)))
        except Exception:
            pass

    # Go: go.mod require
    for p in _walk(root, {"go.mod"}):
        try:
            for ln in open(p, encoding="utf-8", errors="ignore"):
                m = re.match(r"\s*(?:require\s+)?([\w./\-]+)\s+v([0-9][\w.\-+]*)", ln)
                if m and "/" in m.group(1):
                    deps.append(("Go", m.group(1), "v" + m.group(2), rel(p)))
        except Exception:
            pass

    # Maven: pom.xml
    for p in _walk(root, {"pom.xml"}):
        try:
            txt = open(p, encoding="utf-8", errors="ignore").read()
            for m in re.finditer(r"<dependency>(.*?)</dependency>", txt, re.S):
                b = m.group(1)
                g = re.search(r"<groupId>(.*?)</groupId>", b)
                a = re.search(r"<artifactId>(.*?)</artifactId>", b)
                v = re.search(r"<version>(.*?)</version>", b)
                if g and a and v and "$" not in v.group(1):
                    deps.append(("Maven", "%s:%s" % (g.group(1).strip(), a.group(1).strip()), v.group(1).strip(), rel(p)))
        except Exception:
            pass

    # Composer (PHP): composer.lock preferred
    for p in _walk(root, {"composer.lock"}):
        try:
            d = json.load(open(p, encoding="utf-8", errors="ignore"))
            for sec in ("packages", "packages-dev"):
                for pkg in d.get(sec) or []:
                    if pkg.get("name") and pkg.get("version"):
                        deps.append(("Packagist", pkg["name"], _clean_ver(pkg["version"]), rel(p)))
        except Exception:
            pass

    # RubyGems: Gemfile.lock
    for p in _walk(root, {"Gemfile.lock"}):
        try:
            for ln in open(p, encoding="utf-8", errors="ignore"):
                m = re.match(r"\s{4}([A-Za-z0-9_\-]+) \(([0-9][\w.\-]*)\)", ln)
                if m:
                    deps.append(("RubyGems", m.group(1), m.group(2), rel(p)))
        except Exception:
            pass

    # crates.io: Cargo.lock
    for p in _walk(root, {"Cargo.lock"}):
        try:
            txt = open(p, encoding="utf-8", errors="ignore").read()
            for blk in txt.split("[[package]]"):
                n = re.search(r'name\s*=\s*"([^"]+)"', blk)
                v = re.search(r'version\s*=\s*"([^"]+)"', blk)
                if n and v:
                    deps.append(("crates.io", n.group(1), v.group(1), rel(p)))
        except Exception:
            pass

    # NuGet: *.csproj PackageReference
    for p in _walk(root, {".csproj"}):
        try:
            txt = open(p, encoding="utf-8", errors="ignore").read()
            for m in re.finditer(r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"', txt):
                deps.append(("NuGet", m.group(1), _clean_ver(m.group(2)), rel(p)))
        except Exception:
            pass

    # de-dup
    uniq, seen = [], set()
    for e, n, v, mf in deps:
        if v and (e, n, v) not in seen:
            seen.add((e, n, v))
            uniq.append((e, n, v, mf))
    return uniq


def _post(url, payload, timeout=20):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json", "User-Agent": "sca-review"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def _get(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": "sca-review"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def _fixed_version(vuln, ecosystem, name):
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("name") and pkg["name"] != name:
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    return ev["fixed"]
    return ""


def _severity(vuln):
    for s in vuln.get("severity") or []:
        if s.get("score"):
            return s["score"]
    db = (vuln.get("database_specific") or {}).get("severity")
    return db or ""


def scan(root):
    deps = _parse(root)
    if not deps:
        return {"deps": 0, "vulnerable": [], "offline": False, "note": "no dependency manifests/lockfiles found"}
    queries = [{"package": {"name": n, "ecosystem": e}, "version": v} for (e, n, v, _mf) in deps]
    try:
        results = []
        for i in range(0, len(queries), 500):
            r = _post(OSV_BATCH, {"queries": queries[i:i + 500]})
            results.extend(r.get("results") or [])
    except Exception as ex:  # noqa: BLE001 — offline / network blocked
        return {"deps": len(deps), "vulnerable": [], "offline": True,
                "note": "OSV unreachable (%s); dependency inventory returned for manual lookup" % type(ex).__name__,
                "inventory": [{"ecosystem": e, "package": n, "version": v, "manifest": mf} for (e, n, v, mf) in deps[:400]]}
    out, detail_budget = [], _MAX_VULN_DETAIL
    for (e, n, v, mf), res in zip(deps, results):
        ids = [x.get("id") for x in (res.get("vulns") or []) if x.get("id")]
        if not ids:
            continue
        vulns = []
        for vid in ids:
            cve, summary, sev, fixed = vid, "", "", ""
            if detail_budget > 0:
                detail_budget -= 1
                try:
                    d = _get(OSV_VULN + vid)
                    cves = [a for a in (d.get("aliases") or []) if a.startswith("CVE-")]
                    cve = cves[0] if cves else vid
                    summary = (d.get("summary") or "")[:160]
                    sev = _severity(d)
                    fixed = _fixed_version(d, e, n)
                except Exception:
                    pass
            vulns.append({"id": vid, "cve": cve, "severity": sev, "summary": summary, "fixed": fixed})
        out.append({"ecosystem": e, "package": n, "version": v, "manifest": mf, "vulns": vulns})
    return {"deps": len(deps), "vulnerable": out, "offline": False,
            "note": "%d dependencies checked against OSV.dev; %d vulnerable" % (len(deps), len(out))}


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    print(json.dumps(scan(target)))
