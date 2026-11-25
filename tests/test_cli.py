import json

from conftest import fake_openai_key

from invariant.cli import main
from invariant.collectors.sysmon import map_record


def test_demo_runs(capsys):
    assert main(["demo", "--scenario", "promptflux"]) == 0
    out = capsys.readouterr().out
    assert "INV-L3-003" in out and "Metrics" in out


def test_demo_fail_on(capsys):
    assert main(["demo", "--scenario", "jadepuffer", "--fail-on", "critical"]) == 2
    assert main(["demo", "--scenario", "benign", "--fail-on", "low"]) == 0


def test_simulate_then_detect(tmp_path, capsys):
    assert main(["simulate", "all", "-o", str(tmp_path)]) == 0
    out_json = tmp_path / "r.json"
    rc = main(
        [
            "detect",
            "--events",
            str(tmp_path / "lamehug.jsonl"),
            "--respond",
            "--json",
            str(out_json),
            "--learned",
            str(tmp_path / "learned.yaml"),
        ]
    )
    assert rc == 0
    data = json.loads(out_json.read_text())
    assert data["metrics"]["alerts"] >= 4 and data["alerts"][0]["actions"] is not None


def test_hunt_exit_code(tmp_path, capsys):
    (tmp_path / "x.py").write_text(
        f'K="{fake_openai_key()}"\nurl="https://api.openai.com/v1/chat/completions"\n'
    )
    assert main(["hunt", str(tmp_path)]) == 2
    out = capsys.readouterr().out
    assert "HUNT-EMBEDDED-KEY" in out and fake_openai_key() not in out


def test_catalog_formats(capsys):
    assert main(["catalog", "--format", "squid"]) == 0
    assert "acl llm_endpoints dstdomain" in capsys.readouterr().out


def test_jwt_cli(capsys):
    from invariant.identity.jwt_audit import sign_hs

    tok = sign_hs(
        {"alg": "HS256"},
        {"sub": "nacos", "iat": 0, "exp": 1},
        b"SecretKey012345678901234567890123456789012345678901234567890123456789",
    )
    assert main(["jwt", tok]) == 2
    assert json.loads(capsys.readouterr().out)["default_secret"] is True


def test_canary_cli(tmp_path, capsys):
    m = str(tmp_path / "c.json")
    assert main(["canary", "deploy", str(tmp_path / "d"), "--manifest", m]) == 0
    assert main(["canary", "check", "--manifest", m]) == 0
    next((tmp_path / "d").iterdir()).write_text("pwned")
    assert main(["canary", "check", "--manifest", m]) == 2
    assert main(["canary", "watch", "--manifest", m, "--once", "--respond"]) == 2


def test_sysmon_mapping():
    flat = {
        "EventID": 3,
        "Computer": "WS1",
        "UtcTime": "2026-11-20 09:00:00.000",
        "Image": r"C:\w\wscript.exe",
        "ProcessId": "42",
        "DestinationHostname": "api.openai.com",
        "DestinationPort": "443",
        "Initiated": "true",
    }
    e = map_record(flat)
    assert e.kind == "network_connect" and e.pid == 42 and e.dst_port == 443
    beat = {
        "@timestamp": "2026-11-20T09:00:01Z",
        "winlog": {
            "event_id": 1,
            "computer_name": "WS1",
            "event_data": {
                "Image": r"C:\w\cmd.exe",
                "ProcessId": "43",
                "ParentProcessId": "42",
                "CommandLine": "cmd /c whoami",
                "Hashes": "MD5=00,SHA256=ABCDEF",
            },
        },
    }
    e2 = map_record(beat)
    assert e2.kind == "process_start" and e2.ppid == 42 and e2.sha256 == "abcdef"
