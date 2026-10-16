#!/usr/bin/env python3
"""Compute Shodan/FOFA-compatible favicon hashes for a list of hosts/URLs.

Algorithm matches Shodan's `http.favicon.hash` / FOFA's `icon_hash`:
mmh3.hash() of the base64-encoded favicon bytes.
"""
from __future__ import annotations

import argparse
import base64
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

import mmh3

_UA = 'Mozilla/5.0 (X11; Linux x86_64) vrecon/favicon-hash'


def _favicon_url(line: str) -> str | None:
    line = line.strip()
    if not line:
        return None
    if '://' not in line:
        line = f'https://{line}'
    parsed = urlparse(line)
    if not parsed.netloc:
        return None
    return f'{parsed.scheme}://{parsed.netloc}/favicon.ico'


def _dedupe_hosts(lines: list[str]) -> dict[str, str]:
    """Return {host: favicon_url}; first occurrence wins, one fetch per host."""
    result: dict[str, str] = {}
    for line in lines:
        url = _favicon_url(line)
        if not url:
            continue
        host = urlparse(url).netloc
        if host not in result:
            result[host] = url
    return result


def _mmh3_favicon_hash(data: bytes) -> int:
    return mmh3.hash(base64.encodebytes(data))


def _fetch_hash(host: str, url: str, timeout: float) -> tuple[str, int | None]:
    req = urllib.request.Request(url, headers={'User-Agent': _UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
    except (urllib.error.URLError, OSError, TimeoutError):
        return host, None
    if not data:
        return host, None
    try:
        return host, _mmh3_favicon_hash(data)
    except Exception:
        return host, None


def compute_hashes(input_path: Path, output_path: Path, *, timeout: float, threads: int) -> int:
    lines = [l for l in input_path.read_text(encoding='utf-8', errors='ignore').splitlines() if l.strip()]
    targets = _dedupe_hosts(lines)

    results: list[tuple[str, int]] = []
    with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futures = {
            pool.submit(_fetch_hash, host, url, timeout): host
            for host, url in targets.items()
        }
        for fut in as_completed(futures):
            host, h = fut.result()
            if h is not None:
                results.append((host, h))

    results.sort()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    body = '\n'.join(f'{host},{h}' for host, h in results)
    output_path.write_text(body + ('\n' if body else ''), encoding='utf-8')
    return len(results)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Compute Shodan/FOFA-compatible mmh3 favicon hash for a list of hosts/URLs.'
    )
    parser.add_argument('--input', required=True, help='File with one URL or host per line')
    parser.add_argument('--output', required=True, help='Output file (host,hash per line)')
    parser.add_argument('--timeout', type=float, default=10.0, help='Per-host fetch timeout in seconds')
    parser.add_argument('--threads', type=int, default=10, help='Concurrent fetch workers')
    return parser


def main() -> int:
    args = build_parser().parse_args()
    compute_hashes(Path(args.input), Path(args.output), timeout=args.timeout, threads=args.threads)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
