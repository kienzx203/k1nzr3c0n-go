#!/usr/bin/env python3
"""Extract subdomains from OneForAll output (CSV files or SQLite DB fallback)."""
from __future__ import annotations

import argparse
import csv
import sqlite3
from pathlib import Path


def _iter_csv_files(path: Path) -> list[Path]:
    if not path.exists():
        return []
    if path.is_file():
        return [path]
    return list(path.rglob('*.csv'))


def _normalize(value: str) -> str | None:
    value = value.strip().lower()
    if not value:
        return None
    if value.startswith('*.'):
        value = value[2:]
    return value.lstrip('.') or None


def _from_csv(source: Path) -> set[str]:
    results: set[str] = set()
    for csv_path in _iter_csv_files(source):
        try:
            with csv_path.open('r', encoding='utf-8', errors='ignore', newline='') as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    value = row.get('subdomain') if isinstance(row, dict) else None
                    if not value:
                        continue
                    for item in str(value).split(','):
                        normalized = _normalize(item)
                        if normalized:
                            results.add(normalized)
        except OSError:
            continue
    return results


def _from_sqlite(source: Path) -> set[str]:
    """Fallback: read directly from OneForAll's result.sqlite3.
    Used when CSV export didn't run (e.g. timeout before brute completes).
    """
    results: set[str] = set()
    # Look for result.sqlite3 inside the output dir or the default OFA results dir
    candidates = list(source.rglob('result.sqlite3'))
    candidates += [Path('/opt/OneForAll/results/result.sqlite3')]
    for db_path in candidates:
        if not db_path.exists():
            continue
        try:
            con = sqlite3.connect(str(db_path))
            tables = [r[0] for r in
                      con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            for table in tables:
                try:
                    rows = con.execute(f'SELECT subdomain FROM "{table}" WHERE subdomain IS NOT NULL').fetchall()
                    for (sub,) in rows:
                        normalized = _normalize(sub) if sub else None
                        if normalized:
                            results.add(normalized)
                except Exception:
                    continue
            con.close()
            if results:
                break  # found results — stop looking
        except Exception:
            continue
    return results


def extract_oneforall(source: Path, output: Path) -> None:
    results = _from_csv(source)
    if not results:
        # CSV empty or not generated — fall back to SQLite
        results = _from_sqlite(source)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text('\n'.join(sorted(results)) + ('\n' if results else ''), encoding='utf-8')
    print(f'OneForAll extracted: {len(results)} subdomains → {output}')


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Extract subdomains from OneForAll CSV output.')
    parser.add_argument('--input', required=True, help='OneForAll CSV file or directory')
    parser.add_argument('--output', required=True, help='Output file')
    return parser


def main() -> int:
    args = build_parser().parse_args()
    extract_oneforall(Path(args.input), Path(args.output))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
