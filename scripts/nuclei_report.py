#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from collections import defaultdict
from typing import Any


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    if not path.exists():
        return items
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return items


def _safe_name(value: str) -> str:
    return ''.join(ch if ch.isalnum() or ch in '-._' else '_' for ch in value)


def _host_key(item: dict[str, Any]) -> str:
    for key in ('host', 'matched-at', 'url'):
        value = item.get(key)
        if isinstance(value, str) and value:
            if '://' in value:
                value = value.split('://', 1)[1]
            return value.split('/', 1)[0]
    return 'unknown'


def _severity(item: dict[str, Any]) -> str:
    sev = item.get('severity')
    if isinstance(sev, str) and sev:
        return sev.lower()
    return 'unknown'


def _template_id(item: dict[str, Any]) -> str:
    tid = item.get('template-id')
    if isinstance(tid, str) and tid:
        return tid
    info = item.get('info') or {}
    if isinstance(info, dict):
        name = info.get('name')
        if isinstance(name, str) and name:
            return name
    return 'unknown-template'


def _format_finding(item: dict[str, Any]) -> str:
    matched = item.get('matched-at') or item.get('url') or item.get('host') or ''
    return f"- [{_severity(item)}] {_template_id(item)} :: {matched}"


def generate_report(jsonl_paths: list[Path], out_dir: Path) -> None:
    items = []
    for p in jsonl_paths:
        items.extend(_load_jsonl(p))
    out_dir.mkdir(parents=True, exist_ok=True)

    by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_sev: dict[str, int] = defaultdict(int)

    for item in items:
        host = _host_key(item)
        by_host[host].append(item)
        by_sev[_severity(item)] += 1

    # Write per-host files
    host_dir = out_dir / 'nuclei_by_host'
    host_dir.mkdir(parents=True, exist_ok=True)
    for host, findings in sorted(by_host.items()):
        filename = host_dir / f'{_safe_name(host)}.txt'
        lines = [_format_finding(item) for item in findings]
        filename.write_text('\n'.join(lines) + ('\n' if lines else ''), encoding='utf-8')

    # Write summary
    summary = [
        '# Nuclei Summary',
        '',
        f'- Total findings: {len(items)}',
        f'- Total hosts: {len(by_host)}',
        '',
        '## By Severity',
    ]
    for sev, count in sorted(by_sev.items(), key=lambda x: x[0]):
        summary.append(f'- {sev}: {count}')
    summary.append('')
    summary.append('## Hosts')
    for host, findings in sorted(by_host.items()):
        summary.append(f'- {host}: {len(findings)}')
    summary.append('')

    (out_dir / 'summary.md').write_text('\n'.join(summary), encoding='utf-8')


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Generate report from nuclei JSONL output.')
    parser.add_argument('--input', required=True, nargs='+', help='Path(s) to nuclei JSONL files')
    parser.add_argument('--out', required=True, help='Output directory')
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    generate_report([Path(p) for p in args.input], Path(args.out))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
