"""Configuration loading: packaged defaults deep-merged with a user file."""

from __future__ import annotations

import copy
from importlib import resources
from pathlib import Path
from typing import Any

import yaml


def _load_packaged(name: str) -> dict[str, Any]:
    with resources.files("invariant.data").joinpath(name).open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


class Config:
    def __init__(self, data: dict[str, Any], catalog: dict[str, Any], vulndb: dict[str, Any]):
        self.data = data
        self.catalog = catalog
        self.vulndb = vulndb

    @classmethod
    def load(
        cls,
        path: str | Path | None = None,
        catalog_path: str | Path | None = None,
        vulndb_path: str | Path | None = None,
    ) -> Config:
        data = _load_packaged("defaults.yaml")
        if path:
            with open(path, encoding="utf-8") as fh:
                data = deep_merge(data, yaml.safe_load(fh) or {})
        catalog = _load_packaged("llm-endpoints.yaml")
        if catalog_path:
            with open(catalog_path, encoding="utf-8") as fh:
                catalog = deep_merge(catalog, yaml.safe_load(fh) or {})
        vulndb = _load_packaged("vulndb.yaml")
        if vulndb_path:
            with open(vulndb_path, encoding="utf-8") as fh:
                vulndb = deep_merge(vulndb, yaml.safe_load(fh) or {})
        return cls(data, catalog, vulndb)

    def section(self, name: str) -> dict[str, Any]:
        return self.data.get(name, {}) or {}

    def get(self, dotted: str, default: Any = None) -> Any:
        cur: Any = self.data
        for part in dotted.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
        return cur
