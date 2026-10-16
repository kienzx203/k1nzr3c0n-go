#!/usr/bin/env python3
"""One-command backup: SQLite DB (consistent checkpoint) + workflows → tar.gz.

Usage:
    python3 scripts/backup.py [--out /path/to/backup.tar.gz]

Restoring: scripts/restore.py <backup.tar.gz>
"""
from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import tarfile
import tempfile
import time
from pathlib import Path

BASE = Path(os.environ.get("K1NZR3C0N_BASE", "/opt/k1nzr3c0n"))


def main() -> int:
    ap = argparse.ArgumentParser(description="Backup k1nzr3c0n DB + workflows")
    ap.add_argument("--out", default=None, help="Output file (default: BASE/k1nzr3c0n-backup-<ts>.tar.gz)")
    args = ap.parse_args()

    ts = time.strftime("%Y%m%d-%H%M%S")
    out = Path(args.out) if args.out else BASE / f"k1nzr3c0n-backup-{ts}.tar.gz"

    with tempfile.TemporaryDirectory() as td:
        stage = Path(td) / "k1nzr3c0n-backup"
        stage.mkdir()

        # DB — checkpoint WAL first so the copied file is self-contained
        db = BASE / "runs" / "k1nzr3c0n.db"
        if db.exists():
            con = sqlite3.connect(str(db))
            try:
                con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                con.close()
            shutil.copy2(db, stage / "k1nzr3c0n.db")
            print(f"[+] DB: {db} ({db.stat().st_size // 1024} KB)")
        else:
            print(f"[!] DB not found at {db} — skipping")

        # Workflows (skip history snapshots — they bloat backups)
        wf = BASE / "workflows"
        if wf.exists():
            shutil.copytree(wf, stage / "workflows",
                            ignore=shutil.ignore_patterns(".history", "__pycache__"))
            print(f"[+] Workflows: {sum(1 for _ in wf.glob('*.yaml'))} file(s)")

        (stage / "backup-meta.txt").write_text(
            f"created: {ts}\nbase: {BASE}\n", encoding="utf-8"
        )

        out.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(out, "w:gz") as tf:
            tf.add(stage, arcname="k1nzr3c0n-backup")

    print(f"[+] Backup written: {out} ({out.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
