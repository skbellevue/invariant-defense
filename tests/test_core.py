import pytest

from invariant.events import Event, parse_ts
from invariant.exposure.versions import le, lt
from invariant.lineage import ProcessTree


def test_parse_ts_variants():
    assert parse_ts(1_700_000_000) == 1_700_000_000
    assert parse_ts(1_700_000_000_000) == 1_700_000_000
    assert parse_ts("2026-11-20T09:00:00Z") == parse_ts("2026-11-20 09:00:00")


def test_event_roundtrip_and_extra_fields():
    e = Event.from_dict({"kind": "process_start", "ts": 1, "host": "h", "pid": "7", "foo": "bar"})
    assert e.pid == 7 and e.fields["foo"] == "bar"
    again = Event.from_dict(e.to_dict())
    assert again.pid == 7 and again.fields["foo"] == "bar"


def test_unknown_kind_rejected():
    with pytest.raises(ValueError):
        Event.from_dict({"kind": "teleport"})


def test_image_name_cross_platform():
    assert Event("process_start", image=r"C:\Windows\System32\WScript.exe").image_name == "wscript.exe"
    assert Event("process_start", image="/usr/bin/python3").image_name == "python3"


def test_lineage_chain_and_parent_synthesis():
    t = ProcessTree()
    t.observe(
        Event("process_start", 1, "h", pid=10, ppid=1, image="explorer.exe", parent_image="wininit.exe")
    )
    t.observe(Event("process_start", 2, "h", pid=20, ppid=10, image="wscript.exe"))
    t.observe(Event("process_start", 3, "h", pid=30, ppid=20, image="cmd.exe"))
    assert t.chain("h", 30) == "wininit.exe > explorer.exe > wscript.exe > cmd.exe"
    assert t.lineage_pids("h", 30)[:3] == [30, 20, 10]


@pytest.mark.parametrize(
    "a,b,expected",
    [
        ("1.2.9", "1.3.0", True),
        ("1.3.0", "1.3.0", False),
        ("v1.4.0", "1.4.1", True),
        ("1.3.0-beta.1", "1.3.0", True),
        ("2.0.0", "1.4.1", False),
        ("1.10.0", "1.9.0", False),
    ],
)
def test_version_lt(a, b, expected):
    assert lt(a, b) is expected


def test_version_le():
    assert le("2.0.3", "2.0.3") and le("2.0.2", "2.0.3") and not le("2.0.4", "2.0.3")
