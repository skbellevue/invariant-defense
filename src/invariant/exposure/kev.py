"""CISA Known Exploited Vulnerabilities (KEV) catalog support.

Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
Mirror: https://github.com/cisagov/kev-data

Pass a downloaded copy with ``--kev``; ``invariant exposure kev-sync`` fetches it
when the machine has internet access.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def load(path: str) -> dict[str, dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return {v["cveID"]: v for v in data.get("vulnerabilities", []) if "cveID" in v}


def sync(dest: str, url: str = KEV_URL, timeout: float = 30) -> int:
    req = urllib.request.Request(url, headers={"User-Agent": "invariant-defense/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https URL
        body = resp.read()
    data = json.loads(body)
    with open(dest, "wb") as fh:
        fh.write(body)
    return len(data.get("vulnerabilities", []))
