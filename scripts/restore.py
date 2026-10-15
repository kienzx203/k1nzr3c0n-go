#!/usr/bin/env python3
"""Restore a backup produced by scripts/backup.py.

Usage:
    python3 scripts/restore.py /path/to/k1nzr3c0n-backup-<ts>.tar.gz

Safety: the current DB is renamed to k1nzr3c0n.db.pre-restore-<ts> first,
and workflows are merged (existing files are overwritten, extras kept).
Stop services before restoring:  sudo systemctl stop k1nzr3c0n-app k1nzr3c0n-worker k1nzr3c0n-beat
"""
from __future__ import annotations

import argparse
import os
import shutil
import tarfile
import time
from pathlib import Path

BASE = Path(os.environ.get("K1NZR3C0N_BASE", "/opt/k1nzr3c0n"))


def main() -> int:
    ap = argparse.ArgumentParser(description="Restore k1nzr3c0n backup")
    ap.add_argument("backup", help="Path to backup tar.gz")
    ap.add_argument("--yes", action="store_true", help="Skip confirmation prompt")
    args = ap.parse_args()

    src = Path(args.backup)
    if not src.exists():
        print(f"[x] Backup not found: {src}")
        return 2
    with tarfile.open(src) as tf:
        names = tf.getnames()
    if not any(n.startswith("k1nzr3c0n-backup/") for n in names):
        print("[x] Not a k1nzr3c0n backup (missing k1nzr3c0n-backup/ root)")
        return 2

    if not args.yes:
        answer = input(f"This will overwrite the DB at {BASE}/runs/k1nzr3c0n.db.\nType RESTORE to continue: ")
        if answer.strip() != "RESTORE":
            print("Aborted.")
            return 1

    import tempfile
    with tempfile.TemporaryDirectory() as td, tarfile.open(src) as tf:
        tf.extractall(td)
        stage = Path(td) / "k1nzr3c0n-backup"

        db_src = stage / "k1nzr3c0n.db"
        if db_src.exists():
            runs_dir = BASE / "runs"
            runs_dir.mkdir(parents=True, exist_ok=True)
            db_dst = runs_dir / "k1nzr3c0n.db"
            if db_dst.exists():
                keep = db_dst.with_name(f"k1nzr3c0n.db.pre-restore-{time.strftime('%Y%m%d-%H%M%S')}")
                shutil.move(str(db_dst), str(keep))
                print(f"[+] Previous DB kept at: {keep}")
            shutil.copy2(db_src, db_dst)
            print(f"[+] DB restored: {db_dst}")

        wf_src = stage / "workflows"
        if wf_src.exists():
            wf_dst = BASE / "workflows"
            wf_dst.mkdir(parents=True, exist_ok=True)
            for f in wf_src.rglob("*"):
                if f.is_file():
                    shutil.copy2(f, wf_dst / f.relative_to(wf_src))
            print(f"[+] Workflows restored into: {wf_dst}")

    print("[+] Done. Restart services: sudo systemctl restart k1nzr3c0n-app k1nzr3c0n-worker k1nzr3c0n-beat")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
