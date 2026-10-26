#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path


def cleanup(workspace: Path, keep: list[str]) -> None:
    keep_set = {Path(item) for item in keep}
    for path in workspace.iterdir():
        rel = path.relative_to(workspace)
        if rel in keep_set:
            continue
        if path.is_dir():
            for child in path.rglob('*'):
                if child.is_file():
                    child.unlink()
            for child in sorted(path.rglob('*'), reverse=True):
                if child.is_dir():
                    child.rmdir()
            path.rmdir()
        else:
            path.unlink()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Cleanup workspace after run.')
    parser.add_argument('--workspace', required=True, help='Workspace directory')
    parser.add_argument(
        '--keep',
        nargs='+',
        required=True,
        help='Relative paths to keep (e.g. subdomains.txt)',
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    cleanup(Path(args.workspace), args.keep)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
