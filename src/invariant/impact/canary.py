"""Canary files: tripwires that no legitimate process should ever modify.

Ransomware and wipers enumerate directories and rewrite what they find,
generated or not. A canary is cheap, has zero false positives when placed
well, and fires before the valuable files are reached if its name sorts first.
"""

from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from invariant.util import sha256_file

# Names chosen to sort first ("!", "0") and last ("~", "zz") in directory listings
DEFAULT_NAMES = [
    "!_backup_codes.txt",
    "0_passwords_2026.docx",
    "zz_payroll_export.csv",
    "~vault_keys.pdf",
]


@dataclass
class CanaryRecord:
    path: str
    sha256: str
    size: int
    mtime: float


def _content_for(name: str) -> bytes:
    ext = os.path.splitext(name)[1].lower()
    filler = secrets.token_hex(256)
    if ext == ".csv":
        rows = ["employee_id,name,iban_last4,net_pay"] + [
            f"{1000 + i},Employee {i},{secrets.randbelow(9999):04d},{secrets.randbelow(9000) + 1000}"
            for i in range(40)
        ]
        return ("\n".join(rows) + "\n").encode()
    if ext == ".txt":
        return (
            "Recovery codes - do not share\n" + "\n".join(secrets.token_hex(5) for _ in range(12)) + "\n"
        ).encode()
    # binary-ish documents: magic bytes + random low-entropy text so it is not mistaken for ciphertext
    magic = {".docx": b"PK\x03\x04", ".pdf": b"%PDF-1.7\n"}.get(ext, b"")
    return magic + ("CANARY " + filler + "\n").encode() * 8


def deploy(directories: list[str], names: list[str] | None = None) -> list[CanaryRecord]:
    out: list[CanaryRecord] = []
    for d in directories:
        Path(d).mkdir(parents=True, exist_ok=True)
        for name in names or DEFAULT_NAMES:
            p = Path(d) / name
            if not p.exists():
                p.write_bytes(_content_for(name))
            st = p.stat()
            out.append(CanaryRecord(str(p.resolve()), sha256_file(str(p)), st.st_size, st.st_mtime))
    return out


def save_manifest(records: list[CanaryRecord], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"created": time.time(), "canaries": [asdict(r) for r in records]}, fh, indent=2)


def load_manifest(path: str) -> list[CanaryRecord]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return [CanaryRecord(**r) for r in data.get("canaries", [])]


def check(records: list[CanaryRecord]) -> list[dict[str, str]]:
    """Return a list of {'path', 'change'} for canaries that were modified or removed."""
    changes: list[dict[str, str]] = []
    for r in records:
        if not os.path.exists(r.path):
            changes.append({"path": r.path, "change": "deleted_or_renamed"})
            continue
        try:
            h = sha256_file(r.path)
        except OSError as exc:
            changes.append({"path": r.path, "change": f"unreadable: {exc}"})
            continue
        if h != r.sha256:
            changes.append({"path": r.path, "change": "modified"})
    return changes
