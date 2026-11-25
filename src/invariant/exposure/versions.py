"""Tolerant version comparison (no external dependency).

Handles '1.3.0', 'v1.4.1', '2.0.0-ALPHA.1', '1.2.0-beta.1'. Pre-release tags sort
before the release they precede, as in SemVer.
"""

from __future__ import annotations

import re

_PART = re.compile(r"(\d+)|([a-zA-Z]+)")


def _key(v: str) -> tuple:
    v = v.strip().lstrip("vV")
    main, _, pre = v.partition("-")
    nums = [int(x) for x in re.findall(r"\d+", main)][:4]
    nums += [0] * (4 - len(nums))
    if not pre:
        return (*nums, 1, ())
    pre_parts = tuple((0, int(n)) if n else (1, a.lower()) for n, a in _PART.findall(pre))
    return (*nums, 0, pre_parts)


def lt(a: str, b: str) -> bool:
    return _key(a) < _key(b)


def le(a: str, b: str) -> bool:
    return _key(a) <= _key(b)
