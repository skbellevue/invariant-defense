"""Snapshots of configuration and metadata stores, with restore tests.

In-database backups do not help against an attacker with write access to the
database. This module copies exported configuration (files, or the output of
your store's export tool) to a separate location, records hashes, marks the
copy read-only, and measures how long a verified restore takes: the
"configuration-store restore time" metric.

For real immutability put ``dest`` on WORM storage (S3 Object Lock in
compliance mode, an offline disk, ``chattr +i`` on Linux as root).
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import time
from pathlib import Path

from invariant.util import sha256_file


def create(sources: list[str], dest: str, label: str | None = None) -> Path:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    root = Path(dest) / f"{label or 'snapshot'}-{stamp}"
    root.mkdir(parents=True, exist_ok=False)
    manifest: dict[str, dict[str, object]] = {}
    for src in sources:
        s = Path(src)
        files = [s] if s.is_file() else [p for p in s.rglob("*") if p.is_file()]
        for f in files:
            rel = Path(s.name) / f.relative_to(s) if s.is_dir() else Path(s.name)
            target = root / "data" / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, target)
            manifest[str(rel)] = {"sha256": sha256_file(str(target)), "size": target.stat().st_size}
    (root / "MANIFEST.json").write_text(json.dumps({"created": stamp, "files": manifest}, indent=2))
    # read-only: a speed bump, not immutability (see module docstring)
    for p in root.rglob("*"):
        if p.is_file():
            p.chmod(stat.S_IRUSR | stat.S_IRGRP)
    return root


def verify(snapshot_dir: str) -> list[str]:
    root = Path(snapshot_dir)
    data = json.loads((root / "MANIFEST.json").read_text())
    problems: list[str] = []
    for rel, meta in data["files"].items():
        p = root / "data" / rel
        if not p.exists():
            problems.append(f"missing: {rel}")
        elif sha256_file(str(p)) != meta["sha256"]:
            problems.append(f"hash mismatch: {rel}")
    return problems


def restore_test(snapshot_dir: str, scratch: str) -> dict[str, object]:
    """Restore into ``scratch``, verify every hash, report the elapsed time."""
    t0 = time.perf_counter()
    root = Path(snapshot_dir)
    data = json.loads((root / "MANIFEST.json").read_text())
    out = Path(scratch)
    if out.exists():
        for p in out.rglob("*"):
            if p.is_file():
                os.chmod(p, stat.S_IWUSR | stat.S_IRUSR)
        shutil.rmtree(out)
    shutil.copytree(root / "data", out)
    bad = [rel for rel, meta in data["files"].items() if sha256_file(str(out / rel)) != meta["sha256"]]
    return {
        "files": len(data["files"]),
        "verified": len(data["files"]) - len(bad),
        "failed": bad,
        "restore_seconds": round(time.perf_counter() - t0, 3),
    }
