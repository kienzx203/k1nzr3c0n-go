#!/usr/bin/env python3
"""Mine in-scope subdomains from SecurityTrails intel files.

Sources mined (zero network calls, pure local parse):
  - st_ssl.json          hostname-like strings anywhere in observed TLS certs
                         (SANs of HISTORICAL certs — names the subdomain
                         endpoint no longer reports)
  - st_dns_records.txt   record values (NS/MX/A targets), current + historical

Output: <workspace>/st_intel_subs.txt — scope-filtered to the target domain.
Junk that sneaks in is harmless: candidates are re-validated downstream by
the resolve + httpx chain (dead names simply drop out).

Usage: st_intel_mine.py <workspace_dir> <target_domain>
"""
import json
import os
import re
import sys

HOST_RE = re.compile(r"\*?[a-z0-9][a-z0-9._-]*\.[a-z]{2,}", re.I)
VALID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*\.[a-z]{2,}$")


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 1
    workspace, target = sys.argv[1], sys.argv[2].lower()
    found = set()

    # ── st_ssl.json: walk every string in the JSON, collect hostname-like ones
    ssl_path = os.path.join(workspace, "st_ssl.json")
    if os.path.isfile(ssl_path):
        try:
            with open(ssl_path, errors="ignore") as fh:
                data = json.load(fh)
        except Exception:
            data = None

        def walk(obj):
            if isinstance(obj, dict):
                for v in obj.values():
                    walk(v)
            elif isinstance(obj, list):
                for v in obj:
                    walk(v)
            elif isinstance(obj, str):
                for m in HOST_RE.findall(obj):
                    found.add(m.lstrip("*.").lower().rstrip("."))

        walk(data)

    # ── st_dns_records.txt: TYPE<TAB>value<TAB>first_seen<TAB>last_seen
    rec_path = os.path.join(workspace, "st_dns_records.txt")
    if os.path.isfile(rec_path):
        with open(rec_path, errors="ignore") as fh:
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) >= 2:
                    val = parts[1].strip().lower().rstrip(".")
                    if val:
                        found.add(val)

    # ── scope filter: keep only the target itself and its subdomains
    suffix = "." + target
    in_scope = sorted(
        h for h in found
        if (h == target or h.endswith(suffix)) and VALID_RE.match(h)
    )

    out_path = os.path.join(workspace, "st_intel_subs.txt")
    with open(out_path, "w") as fh:
        for h in in_scope:
            fh.write(h + "\n")
    print(f"st_intel_mine: {len(in_scope)} in-scope hosts from ST SSL/DNS intel")
    return 0


if __name__ == "__main__":
    sys.exit(main())
