"""End-to-end: every synthetic scenario must trip the invariants it was built to exercise."""

import pytest
from conftest import rule_ids

from invariant.engine import Engine
from invariant.response.loop import ResponseLoop
from invariant.response.verify import verify_claims, verify_containment
from invariant.simulate import SCENARIOS

EXPECTED = {
    "promptflux": {"INV-L2-001", "INV-L2-004", "INV-L3-003", "INV-L3-004", "INV-L3-005"},
    "lamehug": {"INV-L2-001", "INV-L3-001", "INV-L3-007", "INV-L3-008"},
    "jadepuffer": {
        "INV-L3-006",
        "INV-L3-007",
        "INV-L3-010",
        "INV-L4-001",
        "INV-L4-004",
        "INV-L4-006",
        "INV-L4-007",
        "INV-L5-003",
        "INV-L5-004",
    },
}


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_scenario_detected(name, run):
    ids = rule_ids(run(SCENARIOS[name]()))
    missing = EXPECTED[name] - ids
    assert not missing, f"{name}: missing {missing}; got {sorted(ids)}"


def test_benign_workstation_is_quiet(run):
    alerts = run(SCENARIOS["benign"]())
    assert alerts == [], [a.one_line() for a in alerts]


def test_jadepuffer_never_touches_an_llm_from_the_victim(run):
    # The agent ran remotely: L2 sees nothing, the other invariants carry the detection.
    ids = rule_ids(run(SCENARIOS["jadepuffer"]()))
    assert not any(i.startswith("INV-L2") for i in ids)


def test_response_loop_dry_run_and_approvals(cfg):
    rc = dict(cfg.section("response"))
    loop = ResponseLoop(rc)
    eng = Engine(cfg, on_alert=loop)
    events = SCENARIOS["lamehug"]()
    alerts = eng.run(events)
    first = [a for a in alerts if a.rule_id == "INV-L2-001"][0]
    steps = {a["step"]: a for a in first.actions}
    assert steps["isolate"]["executed"] is False and steps["isolate"]["ok"]
    assert steps["revoke"]["adapter"] == "approval" and "pending" in steps["revoke"]["detail"]
    assert "WS-GOV-007" in eng.ctx.contained
    check = verify_containment(events, "WS-GOV-007", eng.ctx.contained["WS-GOV-007"])
    assert check["outbound_after_containment"] >= 1  # exfil that enforced isolation would have stopped


def test_file_approval_mode(cfg, tmp_path):
    rc = dict(cfg.section("response"))
    rc.update(approval="file", approval_dir=str(tmp_path))
    loop = ResponseLoop(rc)
    Engine(cfg, on_alert=loop).run(SCENARIOS["promptflux"]())
    assert list(tmp_path.glob("*.request.json")), "approval requests should be written for humans/ChatOps"


def test_agent_claims_are_verified_not_trusted():
    res = {r["type"]: r for r in verify_claims(SCENARIOS["jadepuffer"]())}
    assert res["exfiltration"]["verified"] is False
    assert res["account"]["verified"] is True


def test_learned_config_feeds_back(cfg):
    loop = ResponseLoop(dict(cfg.section("response")))
    Engine(cfg, on_alert=loop).run(SCENARIOS["jadepuffer"]())
    learned = loop.learned_config()
    assert learned["notes"]["forged_or_abused_token_fps"]
