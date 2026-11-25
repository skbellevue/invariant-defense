"""File-system hunting: keys, prompts, AI-assistant configs, optional YARA."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from invariant.hunt.aiconfig import audit_config, find_configs
from invariant.hunt.keys import find_keys
from invariant.hunt.prompts import analyze

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache"}


@dataclass
class FileResult:
    path: str
    severity: str
    verdicts: list[dict[str, str]] = field(default_factory=list)
    keys: list[dict[str, Any]] = field(default_factory=list)
    families: dict[str, list[str]] = field(default_factory=dict)
    yara: list[str] = field(default_factory=list)


def _excluded(path: Path, exclude: list[str]) -> bool:
    sp = str(path).replace("\\", "/")
    return any(fnmatch.fnmatch(sp, pat) or fnmatch.fnmatch(path.name, pat) for pat in exclude)


def _iter_files(paths: list[str], max_bytes: int, exclude: list[str] | None = None):
    exclude = exclude or []
    for root in paths:
        p = Path(root)
        if p.is_file():
            yield p
            continue
        for dirpath, dirnames, filenames in os.walk(p):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for f in filenames:
                fp = Path(dirpath) / f
                if _excluded(fp, exclude):
                    continue
                try:
                    if fp.is_file() and fp.stat().st_size <= max_bytes:
                        yield fp
                except OSError:
                    continue


def _load_yara(rules_dir: str | None):
    if not rules_dir:
        return None
    try:
        import yara  # type: ignore
    except ImportError:
        return None
    files = {Path(f).stem: str(f) for f in Path(rules_dir).glob("*.yar")}
    return yara.compile(filepaths=files) if files else None


def scan(
    paths: list[str],
    yara_dir: str | None = None,
    max_bytes: int = 50 * 1024 * 1024,
    exclude: list[str] | None = None,
) -> list[FileResult]:
    """Scan files. ``exclude`` takes globs on the path or file name; exclude your own
    detection content (rule files, this package) the way AV engines exclude their signatures."""
    order = ["info", "low", "medium", "high", "critical"]
    rules = _load_yara(yara_dir)
    results: list[FileResult] = []
    for fp in _iter_files(paths, max_bytes, exclude):
        try:
            data = fp.read_bytes()
        except OSError:
            continue
        views = [data]
        if data.count(b"\x00") > len(data) // 8:  # UTF-16 strings inside binaries
            views.append(data.replace(b"\x00", b""))
        key_hits, fams, verdicts = [], {}, []
        for view in views:
            key_hits += find_keys(view)
        uniq = {k.fingerprint: k for k in key_hits}
        for view in views:
            v = analyze(view, has_key=bool(uniq))
            fams.update(v.families)
            verdicts += [x for x in v.verdicts if x not in verdicts]
        yhits: list[str] = []
        if rules is not None:
            try:
                yhits = [m.rule for m in rules.match(data=data, timeout=30)]
            except Exception:  # noqa: BLE001 - yara errors on odd files are not fatal
                yhits = []
        if not (uniq or verdicts or yhits):
            continue
        sev = max([s for _, s, _ in verdicts] + (["high"] if yhits else []) + ["info"], key=order.index)
        results.append(
            FileResult(
                str(fp),
                sev,
                [{"id": i, "severity": s, "title": t} for i, s, t in verdicts],
                [asdict(k) for k in uniq.values()],
                fams,
                yhits,
            )
        )
    results.sort(key=lambda r: order.index(r.severity), reverse=True)
    return results


def scan_ai_configs(paths: list[str], provider_domains: list[str]):
    findings = []
    for root in paths:
        for cfg in find_configs(root):
            findings.extend(audit_config(cfg, provider_domains))
    return findings
