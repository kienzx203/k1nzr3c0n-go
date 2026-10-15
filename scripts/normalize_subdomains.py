#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path


_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')
_HOST_RE = re.compile(r'([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+)', re.IGNORECASE)


def _normalize_line(line: str) -> str | None:
    line = line.strip().lower()
    if not line:
        return None
    if line.startswith('*.'):
        line = line[2:]
    line = line.lstrip('.')
    line = line.split()[0]
    return line


def _is_valid_hostname(value: str) -> bool:
    if len(value) > 253:
        return False
    if value.endswith('.'):
        value = value[:-1]
    labels = value.split('.')
    if any(not label for label in labels):
        return False
    allowed = re.compile(r'^[a-z0-9-]+$')
    for label in labels:
        if len(label) > 63:
            return False
        if label.startswith('-') or label.endswith('-'):
            return False
        if not allowed.match(label):
            return False
    return True


def _extract_candidates(raw_line: str, target: str) -> list[str]:
    line = _ANSI_RE.sub('', raw_line)
    candidates = []
    for match in _HOST_RE.finditer(line):
        candidate = match.group(1).lower().strip()
        if candidate.endswith(target):
            candidates.append(candidate)
    return candidates


def normalize_file(input_path: Path, output_path: Path, target: str) -> None:
    target = target.lower().strip()
    target = target.lstrip('.')
    results: set[str] = set()
    for raw in input_path.read_text(encoding='utf-8', errors='ignore').splitlines():
        candidates = _extract_candidates(raw, target)
        if not candidates:
            line = _normalize_line(raw)
            if line and line.endswith(target):
                candidates = [line]
        for line in candidates:
            if not _is_valid_hostname(line):
                continue
            results.add(line)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text('\n'.join(sorted(results)) + ('\n' if results else ''), encoding='utf-8')


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Normalize subdomain lists.')
    parser.add_argument('--input', required=True, help='Input file')
    parser.add_argument('--output', required=True, help='Output file')
    parser.add_argument('--target', required=True, help='Base domain to keep')
    return parser


def main() -> int:
    args = build_parser().parse_args()
    normalize_file(Path(args.input), Path(args.output), args.target)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
