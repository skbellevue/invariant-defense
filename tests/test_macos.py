"""macOS support: eslogger mapping, s1ngularity replay, pf isolation, streaming, immutable snapshots.

These tests run on any OS (the eslogger records are fixtures); the macOS CI job
additionally exercises the platform-specific paths (chflags, pf adapter resolution).
"""

import json
import platform
import sys

import pytest
from conftest import rule_ids

from invariant.collectors.eslogger import CS_ADHOC, CS_VALID, iter_lines, map_record, signed_state
from invariant.events import Event
from invariant.response.actions import (
    PF_ANCHOR,
    Actions,
    pf_isolation_commands,
    pf_isolation_rules,
    resolve_adapter,
)
from invariant.simulate import s1ngularity, s1ngularity_eslogger


def proc(pid=10, ppid=1, path="/bin/zsh", **kw):
    d = {"audit_token": {"pid": pid, "euid": 501}, "ppid": ppid, "executable": {"path": path}}
    d.update(kw)
    return d


def rec(name, body, p=None, t="2026-11-20T09:00:00Z"):
    return {"schema_version": 1, "time": t, "process": p or proc(), "event": {name: body}}


# ------------------------------------------------------------------ mapping
def test_exec_maps_new_image_args_ppid_and_signing():
    target = proc(11, 10, "/opt/homebrew/bin/claude", codesigning_flags=CS_VALID, team_id="ABCDE12345")
    e = map_record(
        rec("exec", {"target": target, "args": ["claude", "-p", "hi"], "cwd": {"path": "/tmp"}}), "mac"
    )
    assert e.kind == "process_start" and e.host == "mac"
    assert (e.pid, e.ppid, e.image_name, e.cmdline) == (11, 10, "claude", "claude -p hi")
    assert e.signed is True and e.fields["cwd"] == "/tmp" and e.fields["source"] == "eslogger"


def test_create_both_union_shapes():
    new = map_record(
        rec(
            "create",
            {
                "destination_type": 1,
                "destination": {"new_path": {"dir": {"path": "/tmp"}, "filename": "a.sh"}},
            },
        )
    )
    existing = map_record(
        rec("create", {"destination_type": 0, "destination": {"existing_file": {"path": "/tmp/b"}}})
    )
    assert new.kind == "file_write" and new.path == "/tmp/a.sh"
    assert existing.path == "/tmp/b"


def test_close_only_when_modified_rename_unlink():
    assert map_record(rec("close", {"modified": False, "target": {"path": "/x"}})) is None
    assert map_record(rec("close", {"modified": True, "target": {"path": "/x"}})).kind == "file_write"
    r = map_record(
        rec(
            "rename",
            {
                "source": {"path": "/d/f.txt"},
                "destination_type": 1,
                "destination": {"new_path": {"dir": {"path": "/d"}, "filename": "f.txt.locked"}},
            },
        )
    )
    assert (r.kind, r.path, r.target_path) == ("file_rename", "/d/f.txt", "/d/f.txt.locked")
    u = map_record(rec("unlink", {"target": {"path": "/d/g"}, "parent_dir": {"path": "/d"}}))
    assert u.kind == "file_delete" and u.path == "/d/g"


def test_unknown_and_malformed_records_are_skipped():
    assert map_record(rec("mmap", {"source": {"path": "/x"}})) is None
    assert map_record({"no": "event"}) is None
    lines = ["", "garbage", '{"event": {"unlink": {"target": {"path": "/a"}}}}', "{not json"]
    assert [e.path for e in iter_lines(lines, "h")] == ["/a"]


@pytest.mark.parametrize(
    "p,expected",
    [
        ({"is_platform_binary": True}, True),
        ({"codesigning_flags": CS_VALID, "team_id": "ABCDE12345"}, True),
        ({"codesigning_flags": CS_VALID | CS_ADHOC}, False),
        ({"codesigning_flags": 0}, False),
        ({}, None),
    ],
)
def test_signed_state(p, expected):
    assert signed_state(p) is expected


def test_unsigned_script_host_to_model_is_critical(run):
    """Signing state from eslogger feeds L2 severity."""
    events = [
        map_record(
            rec(
                "exec",
                {
                    "target": proc(50, 1, "/tmp/helper", codesigning_flags=CS_VALID | CS_ADHOC),
                    "args": ["/tmp/helper"],
                },
            ),
            "mac",
        ),
        Event(
            "network_connect",
            1e10,
            "mac",
            pid=50,
            image="/usr/bin/osascript",
            dst_host="api.openai.com",
            signed=False,
        ),
    ]
    a = [x for x in run(events) if x.rule_id == "INV-L2-001"][0]
    assert a.severity == "critical"


# ------------------------------------------------------------------ replay
def test_s1ngularity_replay(run):
    alerts = run(s1ngularity())
    ids = rule_ids(alerts)
    assert {"INV-L3-009", "INV-L3-004", "INV-L3-002"} <= ids
    cli = [a for a in alerts if a.rule_id == "INV-L3-009"]
    assert len(cli) == 2 and all(a.severity == "critical" for a in cli)
    zshrc = [a for a in alerts if a.rule_id == "INV-L3-004" and a.evidence["path"].endswith(".zshrc")][0]
    assert zshrc.attack == ["T1546.004"]


def test_launch_agent_persistence_technique(run):
    alerts = run(
        [
            Event(
                "file_write",
                1,
                "mac",
                pid=5,
                image="/tmp/x",
                path="/Users/a/Library/LaunchAgents/com.update.plist",
            )
        ]
    )
    a = [x for x in alerts if x.rule_id == "INV-L3-004"][0]
    assert a.attack == ["T1543.001"]


def test_macos_recon_burst(run):
    evs = [Event("process_start", 0, "mac", pid=60, ppid=1, image="/tmp/agent")]
    for i, c in enumerate(
        ["sw_vers", "system_profiler SPHardwareDataType", "dscl . list /Users", "csrutil status"]
    ):
        evs.append(
            Event(
                "process_start", 1 + i, "mac", pid=61 + i, ppid=60, image="/bin/zsh", cmdline=f"zsh -c '{c}'"
            )
        )
    assert "INV-L3-007" in rule_ids(run(evs))


def test_boot_volume_is_not_removable_media(run):
    evs = [
        Event("process_start", 0, "mac", pid=70, ppid=1, image="/usr/bin/osascript"),
        Event(
            "file_write",
            1,
            "mac",
            pid=70,
            image="/usr/bin/osascript",
            path="/Volumes/Macintosh HD/Users/a/x.scpt",
        ),
        Event("file_write", 2, "mac", pid=70, image="/usr/bin/osascript", path="/Volumes/USB/x.scpt"),
    ]
    spread = [a for a in run(evs) if a.rule_id == "INV-L3-005"]
    assert [a.evidence["path"] for a in spread] == ["/Volumes/USB/x.scpt"]


# ------------------------------------------------------------------ response
def test_pf_rules_and_commands():
    rules = pf_isolation_rules(["10.0.0.0/24"])
    assert rules.splitlines() == [
        "pass quick on lo0 all",
        "pass out quick to 10.0.0.0/24 keep state",
        "pass in quick from 10.0.0.0/24 keep state",
        "block drop quick all",
    ]
    assert pf_isolation_commands([])[0] == ["pfctl", "-a", PF_ANCHOR, "-f", "-"]
    assert PF_ANCHOR.startswith("com.apple/")  # evaluated by the stock pf.conf anchor


def test_auto_adapter_resolution():
    assert resolve_adapter("auto", "Darwin") == "pf"
    assert resolve_adapter("auto", "Linux") == "iptables"
    assert resolve_adapter("auto", "Windows") == "log"
    assert resolve_adapter("webhook", "Darwin") == "webhook"


def test_pf_dry_run_description():
    from invariant.alerts import Alert

    acts = Actions({"dry_run": True, "adapters": {"isolate": "pf"}, "management_cidrs": ["10.0.0.0/24"]})
    res = acts.run("isolate", Alert("X", "t", "high", "L3", "mac", 0))
    assert not res.executed and PF_ANCHOR in res.detail and "block drop quick all" in res.detail


# ------------------------------------------------------------------ CLI
def test_stream_eslogger_from_file(tmp_path, capsys):
    from invariant.cli import main

    f = tmp_path / "es.jsonl"
    f.write_text("".join(json.dumps(r) + "\n" for r in s1ngularity_eslogger()))
    assert main(["stream", "--format", "eslogger", "--events", str(f), "--fail-on", "critical"]) == 2
    out = capsys.readouterr().out
    assert "INV-L3-009" in out and "INV-L3-004" in out


def test_detect_eslogger_format(tmp_path, capsys):
    from invariant.cli import main

    f = tmp_path / "es.jsonl"
    f.write_text("".join(json.dumps(r) + "\n" for r in s1ngularity_eslogger()))
    assert main(["detect", "--format", "eslogger", "--events", str(f), "--fail-on", "high"]) == 2


def test_unisolate_dry_run(capsys):
    from invariant.cli import main

    assert main(["unisolate", "--adapter", "pf"]) == 0
    assert "pfctl -a com.apple/invariant -F all" in capsys.readouterr().out


@pytest.mark.skipif(platform.system() != "Darwin", reason="chflags is macOS-only")
def test_immutable_snapshot_on_macos(tmp_path):
    import subprocess

    from invariant.impact import snapshot

    src = tmp_path / "cfg"
    src.mkdir()
    (src / "a.yaml").write_text("x: 1\n")
    snap = snapshot.create([str(src)], str(tmp_path / "vault"), "cfg", immutable=True)
    target = next((snap / "data").rglob("a.yaml"))
    with pytest.raises(PermissionError):
        target.write_text("tampered")
    # clean up so pytest can remove tmp_path
    subprocess.run(["chflags", "-R", "nouchg", str(tmp_path / "vault")], check=True)


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS-only")
def test_auto_resolves_to_pf_on_this_mac():
    assert resolve_adapter("auto") == "pf"
