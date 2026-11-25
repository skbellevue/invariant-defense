import json
from datetime import date
from pathlib import Path

from invariant.exposure import kev as kevmod
from invariant.exposure.inventory import coverage, evaluate, load_estate

EXAMPLE = Path(__file__).resolve().parents[1] / "config" / "ai-estate.example.yaml"


def test_example_estate_findings(cfg):
    estate = load_estate(str(EXAMPLE))
    findings = evaluate(estate, cfg.vulndb, today=date(2026, 11, 24))
    rules = {(f.asset, f.rule) for f in findings}
    assert ("langflow-public", "CVE-2025-3248") in rules
    assert ("nacos-prod", "CVE-2021-29441") in rules
    assert ("nacos-prod", "INV-NACOS-DEFAULT-TOKEN-KEY") in rules
    assert ("minio-artifacts", "INV-MINIO-DEFAULT-ROOT") in rules
    assert ("ollama-gpu-01", "INV-OLLAMA-EXPOSED") in rules
    assert not any(a == "langflow-internal" and r == "CVE-2025-3248" for a, r in rules)
    lf = [f for f in findings if f.rule == "CVE-2025-3248"][0]
    assert lf.severity == "critical" and lf.details["kev"]


def test_kev_feed_overrides_builtin(tmp_path, cfg):
    feed = tmp_path / "kev.json"
    feed.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2021-29441",
                        "dueDate": "2099-01-01",
                        "knownRansomwareCampaignUse": "Unknown",
                    }
                ]
            }
        )
    )
    kev = kevmod.load(str(feed))
    estate = {
        "assets": [
            {"name": "n", "product": "nacos", "version": "1.4.0", "internet_facing": True, "owner": "x"},
            {"name": "l", "product": "langflow", "version": "1.2.0", "internet_facing": True, "owner": "x"},
        ]
    }
    findings = {f.rule: f for f in evaluate(estate, cfg.vulndb, kev)}
    assert (
        findings["CVE-2021-29441"].details["kev"]
        and findings["CVE-2021-29441"].details["kev_due"] == "2099-01-01"
    )
    # the feed is authoritative when supplied
    assert not findings["CVE-2025-3248"].details["kev"]


def test_coverage_metrics():
    cov = coverage(load_estate(str(EXAMPLE)))
    assert cov["ai_assets"] >= 5 and 0 < cov["egress_telemetry_coverage"] <= 1
