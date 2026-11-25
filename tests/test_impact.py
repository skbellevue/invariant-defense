import os

from conftest import rule_ids

from invariant.events import Event
from invariant.impact import canary, snapshot


def test_canary_deploy_check_and_detect(tmp_path, cfg, run):
    recs = canary.deploy([str(tmp_path / "share")])
    manifest = tmp_path / "m.json"
    canary.save_manifest(recs, str(manifest))
    assert canary.check(canary.load_manifest(str(manifest))) == []
    victim = recs[0].path
    with open(victim, "ab") as fh:
        fh.write(b"encrypted")
    os.remove(recs[1].path)
    changes = {c["change"] for c in canary.check(recs)}
    assert changes == {"modified", "deleted_or_renamed"}
    cfg.data["impact"]["canary_manifest"] = str(manifest)
    alerts = run(
        [Event("file_rename", 1, "h", pid=9, image="evil", path=victim, target_path=victim + ".locked")], cfg
    )
    assert "INV-L5-001" in rule_ids(alerts)


def test_destructive_rate(run):
    evs = [
        Event(
            "file_rename",
            i * 0.5,
            "h",
            pid=5,
            image="locker",
            path=f"/d/f{i}.txt",
            target_path=f"/d/f{i}.txt.enc",
        )
        for i in range(60)
    ]
    a = [x for x in run(evs) if x.rule_id == "INV-L5-002"][0]
    assert a.evidence["dominant_new_extension"] == ".enc"


def test_high_entropy_writes_count(run):
    evs = [Event("file_write", i, "h", pid=6, image="w", path=f"/d/{i}", entropy=7.9) for i in range(55)]
    assert "INV-L5-002" in rule_ids(run(evs))


def test_slow_benign_writes_do_not_trigger(run):
    evs = [Event("file_write", i * 10, "h", pid=6, image="w", path=f"/d/{i}", entropy=7.9) for i in range(55)]
    assert "INV-L5-002" not in rule_ids(run(evs))


def test_sql_guard(run):
    evs = [
        Event(
            "sql",
            i,
            "db",
            fields={
                "session": "s",
                "statement": f"UPDATE config_info SET content='x' WHERE id={i}",
                "rows": 25,
            },
        )
        for i in range(10)
    ]
    evs.append(Event("sql", 20, "db", fields={"session": "s", "statement": "DROP TABLE his_config_info"}))
    alerts = run(evs)
    ids = rule_ids(alerts)
    assert {"INV-L5-004", "INV-L5-003"} <= ids
    assert all(a.severity == "critical" for a in alerts if a.rule_id.startswith("INV-L5"))


def test_snapshot_roundtrip(tmp_path):
    src = tmp_path / "nacos-export"
    src.mkdir()
    (src / "app.yaml").write_text("db: prod\n")
    (src / "sub").mkdir()
    (src / "sub" / "feature.properties").write_text("flag=true\n")
    snap = snapshot.create([str(src)], str(tmp_path / "vault"), "nacos")
    assert snapshot.verify(str(snap)) == []
    res = snapshot.restore_test(str(snap), str(tmp_path / "restore"))
    assert res["verified"] == 2 and not res["failed"] and res["restore_seconds"] >= 0
    # tamper detection
    target = next((snap / "data").rglob("app.yaml"))
    os.chmod(target, 0o600)
    target.write_text("db: attacker\n")
    assert snapshot.verify(str(snap))
