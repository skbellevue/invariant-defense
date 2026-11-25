from conftest import rule_ids

from invariant.egress.catalog import EndpointCatalog
from invariant.egress.policy import EgressPolicy
from invariant.events import Event


def test_catalog_domain_pattern_port_path(cfg):
    cat = EndpointCatalog(cfg.catalog)
    assert cat.match_host("generativelanguage.googleapis.com").provider == "google_gemini"
    assert (
        cat.match_host("eu.api.openai.com") is None
        or cat.match_host("eu.api.openai.com").provider == "openai"
    )
    assert cat.match_host("bedrock-runtime.us-east-1.amazonaws.com").provider == "aws_bedrock"
    assert cat.match_host("example.com") is None
    assert cat.match_port(11434).provider == "ollama"
    assert cat.match_path("http://10.0.0.5:8000/v1/chat/completions").provider == "openai_compatible"


def test_policy_allows_sanctioned_and_flags_script_host(cfg):
    pol = EgressPolicy(cfg.section("egress"))
    ok = pol.evaluate(Event("network_connect", host="dev-sam", image="/usr/local/bin/claude"), "anthropic")
    assert ok.allowed
    bad = pol.evaluate(
        Event("network_connect", host="ws1", image=r"C:\Windows\System32\wscript.exe"), "google_gemini"
    )
    assert not bad.allowed and bad.high_risk_process
    # same assistant on a non-developer host is not covered by the developer rule
    assert not pol.evaluate(Event("network_connect", host="fin-01", image="claude"), "anthropic").allowed


def _conn(ts, host, pid, image, dst, signed=None, port=443):
    return Event(
        "network_connect", ts, host, pid=pid, image=image, dst_host=dst, dst_port=port, signed=signed
    )


def test_llm_egress_severity(run):
    alerts = run([_conn(1, "ws1", 5, r"C:\w\wscript.exe", "generativelanguage.googleapis.com", signed=False)])
    a = [x for x in alerts if x.rule_id == "INV-L2-001"][0]
    assert a.severity == "critical" and a.evidence["provider"] == "google_gemini"
    alerts = run([_conn(1, "ws1", 6, r"C:\apps\tool.exe", "api.openai.com", signed=True)])
    assert [x.severity for x in alerts if x.rule_id == "INV-L2-001"] == ["medium"]


def test_sanctioned_egress_is_silent(run):
    assert run([_conn(1, "dev-laptop", 7, "/usr/bin/code", "api.anthropic.com")]) == []


def test_periodic_model_calls_detected(run):
    evs = [
        _conn(i * 3600 + (i % 2) * 5, "ws1", 5, "wscript.exe", "generativelanguage.googleapis.com")
        for i in range(5)
    ]
    assert "INV-L2-004" in rule_ids(run(evs))


def test_generic_beacon_vs_jittery_traffic(run):
    regular = [_conn(i * 1800, "srv", 9, "python3", None) for i in range(5)]
    for e in regular:
        e.dst_host, e.dst_ip = None, "192.0.2.10"
    assert "INV-L3-010" in rule_ids(run(regular))
    jittery = [_conn(t, "srv", 9, "python3", "x.example") for t in (0, 100, 2000, 2100, 9000)]
    assert "INV-L3-010" not in rule_ids(run(jittery))


def test_key_reuse_across_hosts(run):
    evs = [
        Event(
            "http_request", 1, "a", image="svc", dst_host="api.openai.com", fields={"api_key_fp": "sha256:k1"}
        ),
        Event(
            "http_request", 2, "b", image="svc", dst_host="api.openai.com", fields={"api_key_fp": "sha256:k1"}
        ),
    ]
    assert "INV-L2-002" in rule_ids(run(evs))


def test_known_bad_key_in_use(cfg, run):
    cfg.data["egress"]["known_bad_key_fps"] = ["sha256:bad"]
    evs = [
        Event(
            "http_request",
            1,
            "a",
            image="svc",
            dst_host="api.openai.com",
            fields={"api_key_fp": "sha256:bad"},
        )
    ]
    assert "INV-L2-003" in rule_ids(run(evs, cfg))
