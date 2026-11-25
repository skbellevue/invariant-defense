"""macOS Network Extension integration: record contract, log-stream parsing, config export,
multi-source streaming with re-ordering, and the eslogger + Network Extension join."""

import json
import os
import threading
from pathlib import Path

from conftest import rule_ids

from invariant.cli import _follow, main
from invariant.collectors.eslogger import CS_ADHOC, CS_VALID
from invariant.collectors.eslogger import map_record as es_map
from invariant.collectors.nefilter import LOG_PREFIX, SUBSYSTEM, export_config, iter_lines, map_line
from invariant.events import Event

FIXTURE = Path(__file__).parent / "fixtures" / "nefilter_flow.json"


def contract() -> dict:
    return json.loads(FIXTURE.read_text())


def test_contract_fixture_maps_to_event():
    """The same fixture is asserted by the Swift tests (FlowRecord.jsonLine)."""
    e = map_line(json.dumps(contract()))
    assert e.kind == "network_connect"
    assert (e.pid, e.ppid, e.image_name, e.dst_host, e.dst_ip, e.dst_port) == (
        7200,
        7100,
        "claude",
        "api.anthropic.com",
        "160.79.104.10",
        443,
    )
    assert e.signed is True and e.user == "uid:501"
    assert e.fields["team_id"] == "ABCDE12345" and e.fields["protocol"] == "tcp"


def test_log_stream_ndjson_wrapper():
    wrapped = {
        "timestamp": "2026-11-25 14:00:00.123456-0800",
        "subsystem": SUBSYSTEM,
        "category": "flows",
        "processImagePath": "/Library/SystemExtensions/X/com.skbellevue.invariant.netfilter.extension",
        "eventMessage": LOG_PREFIX + json.dumps(contract(), separators=(",", ":")),
    }
    e = map_line(json.dumps(wrapped))
    assert e is not None and e.dst_host == "api.anthropic.com"


def test_non_flow_lines_are_skipped():
    lines = [
        'Filtering the log data using "subsystem == ..."',  # log stream banner
        json.dumps({"eventMessage": "invariant netfilter starting, mode=all", "subsystem": SUBSYSTEM}),
        json.dumps({"eventMessage": LOG_PREFIX + "{broken"}),
        json.dumps({"kind": "process_start", "pid": 1}),
        "",
        json.dumps(contract()),
    ]
    assert [e.pid for e in iter_lines(lines)] == [7200]


def test_export_config_matches_swift_keys(cfg):
    conf = export_config(cfg.catalog)
    assert conf["mode"] == "catalog"
    assert "api.openai.com" in conf["domains"] and "router.huggingface.co" in conf["domains"]
    assert 11434 in conf["ports"]
    # FilterConfig.CodingKeys in macos/InvariantNetFilter/Sources/InvariantFlowCore/FilterConfig.swift
    assert set(conf) == {"mode", "domains", "ports", "write_file", "unified_log", "max_file_bytes"}
    assert export_config(cfg.catalog, "all")["mode"] == "all"


def test_catalog_cli_nefilter(capsys):
    assert main(["catalog", "--format", "nefilter"]) == 0
    assert json.loads(capsys.readouterr().out)["mode"] == "catalog"


def _join_events():
    """osascript (ad-hoc signed helper) asks OpenAI, then spawns zsh: needs both sensors."""
    helper = {
        "audit_token": {"pid": 50, "euid": 501},
        "ppid": 1,
        "executable": {"path": "/tmp/.helper"},
        "codesigning_flags": CS_VALID | CS_ADHOC,
    }
    launcher = {
        "audit_token": {"pid": 40, "euid": 501},
        "ppid": 1,
        "executable": {"path": "/bin/zsh"},
        "is_platform_binary": True,
    }
    exec_helper = es_map(
        {
            "time": "2026-11-20T09:00:00Z",
            "process": launcher,
            "event": {"exec": {"target": helper, "args": ["/tmp/.helper"]}},
        },
        "mac",
    )
    zsh = {
        "audit_token": {"pid": 51, "euid": 501},
        "ppid": 50,
        "executable": {"path": "/bin/zsh"},
        "is_platform_binary": True,
    }
    exec_zsh = es_map(
        {
            "time": "2026-11-20T09:00:04Z",
            "process": helper,
            "event": {"exec": {"target": zsh, "args": ["zsh", "-c", "whoami"]}},
        },
        "mac",
    )
    flow = map_line(
        json.dumps(
            {
                **contract(),
                "host": "mac",
                "pid": 50,
                "ppid": 1,
                "image": "/tmp/.helper",
                "signed": False,
                "dst_host": "api.openai.com",
                "dst_ip": "162.159.140.245",
                "ts": exec_zsh.ts - 2,
            }
        )
    )
    return exec_helper, flow, exec_zsh


def test_eslogger_and_network_extension_join(run):
    alerts = run(list(_join_events()))
    by = {a.rule_id: a for a in alerts}
    assert by["INV-L2-001"].severity == "high"  # unsigned (ad-hoc) helper -> model API
    assert by["INV-L3-001"].severity == "critical"  # ...then executed a shell


def _write_jsonl(path, events):
    path.write_text("".join(json.dumps(e.to_dict()) + "\n" for e in events))


def test_stream_reorders_late_arriving_flows(tmp_path, capsys):
    exec_helper, flow, exec_zsh = _join_events()
    f = tmp_path / "mixed.jsonl"
    _write_jsonl(f, [exec_helper, exec_zsh, flow])  # the flow record arrives last (log latency)
    assert main(["stream", "--events", str(f), "--min-severity", "high", "--reorder-ms", "0"]) == 0
    assert "INV-L3-001" not in capsys.readouterr().out  # without re-ordering the join is missed
    assert main(["stream", "--events", str(f), "--min-severity", "high"]) == 0
    assert "INV-L3-001" in capsys.readouterr().out


def test_stream_needs_a_source(capsys):
    assert main(["stream", "--events", "none"]) == 1


def test_follow_survives_rotation(tmp_path):
    p = tmp_path / "flows.jsonl"
    p.write_text("a\nb\n")
    stop = threading.Event()
    gen = _follow(str(p), from_start=True, poll_s=0.01, stop=stop)
    assert [next(gen), next(gen)] == ["a\n", "b\n"]
    os.rename(p, tmp_path / "flows.jsonl.1")  # what RotatingWriter does
    p.write_text("c\n")
    assert next(gen) == "c\n"
    with open(p, "a") as fh:
        fh.write("d\n")
    assert next(gen) == "d\n"
    stop.set()


def test_simulate_writes_nefilter_records(tmp_path, capsys):
    assert main(["simulate", "s1ngularity", "-o", str(tmp_path)]) == 0
    flows = list(iter_lines((tmp_path / "s1ngularity.nefilter.jsonl").read_text().splitlines()))
    assert {e.dst_host for e in flows} >= {"api.anthropic.com", "api.github.com"}
    assert (
        main(
            [
                "detect",
                "--format",
                "nefilter",
                "--events",
                str(tmp_path / "s1ngularity.nefilter.jsonl"),
                "--fail-on",
                "medium",
            ]
        )
        == 2
    )


def test_s1ngularity_with_network_extension(run):
    from invariant.simulate import s1ngularity

    ids = rule_ids(run(s1ngularity()))
    assert {"INV-L2-001", "INV-L3-009", "INV-L3-004"} <= ids


def test_event_roundtrip_keeps_nefilter_source():
    e = Event.from_dict(contract())
    assert e.to_dict()["fields"]["source"] == "nefilter"
