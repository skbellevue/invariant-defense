from conftest import rule_ids

from invariant.events import Event


def P(ts, host, pid, ppid, image, cmd="", parent=None):
    return Event("process_start", ts, host, pid=pid, ppid=ppid, image=image, cmdline=cmd, parent_image=parent)


def test_query_then_exec(run):
    evs = [
        P(0, "h", 10, 1, "stealer.exe"),
        Event(
            "network_connect",
            1,
            "h",
            pid=10,
            image="stealer.exe",
            dst_host="router.huggingface.co",
            dst_port=443,
        ),
        P(5, "h", 11, 10, r"C:\Windows\System32\cmd.exe", "cmd /c whoami"),
    ]
    alerts = run(evs)
    a = [x for x in alerts if x.rule_id == "INV-L3-001"][0]
    assert a.severity == "critical" and a.evidence["seconds_after_query"] == 4


def test_query_then_exec_outside_window_is_silent(run):
    evs = [
        P(0, "h", 10, 1, "stealer.exe"),
        Event("network_connect", 1, "h", pid=10, image="stealer.exe", dst_host="router.huggingface.co"),
        P(10_000, "h", 11, 10, "cmd.exe"),
    ]
    assert "INV-L3-001" not in rule_ids(run(evs))


def test_sanctioned_coding_agent_running_commands_is_not_an_alert(run):
    evs = [
        P(0, "dev-1", 20, 1, "/opt/homebrew/bin/claude", "claude", "/bin/zsh"),
        Event(
            "network_connect",
            1,
            "dev-1",
            pid=20,
            image="/opt/homebrew/bin/claude",
            dst_host="api.anthropic.com",
        ),
        P(2, "dev-1", 21, 20, "/bin/bash", "bash -c 'pytest'"),
    ]
    assert rule_ids(run(evs)) == set()


def test_generated_script_written_then_run(run):
    evs = [
        P(0, "h", 30, 1, "dropper.exe"),
        Event(
            "file_write", 10, "h", pid=30, image="dropper.exe", path=r"C:\Users\u\AppData\Local\Temp\x.ps1"
        ),
        P(20, "h", 31, 30, "powershell.exe", r"powershell -f C:\Users\u\AppData\Local\Temp\x.ps1"),
    ]
    assert "INV-L3-002" in rule_ids(run(evs))


def test_dev_tool_written_script_is_fine(run):
    evs = [
        Event("file_write", 10, "h", pid=40, image="/usr/bin/code", path="/src/test_a.py"),
        P(20, "h", 41, 1, "/usr/bin/python3", "python3 /src/test_a.py"),
    ]
    assert "INV-L3-002" not in rule_ids(run(evs))


def test_self_rewrite_and_persistence_and_spread(run):
    vbs = r"C:\Users\a\AppData\Local\Temp\s.vbs"
    cmd = f'wscript.exe "{vbs}"'
    evs = [P(0, "h", 50, 1, "wscript.exe", cmd)]
    for i in range(3):
        evs.append(
            Event(
                "file_write",
                10 + i,
                "h",
                pid=50,
                image="wscript.exe",
                cmdline=cmd,
                path=vbs,
                sha256=f"{i:064x}",
            )
        )
    evs.append(
        Event(
            "file_write",
            20,
            "h",
            pid=50,
            image="wscript.exe",
            cmdline=cmd,
            path=r"C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\s.vbs",
            sha256="2" * 64,
        )
    )
    evs.append(
        Event(
            "file_write", 30, "h", pid=50, image="wscript.exe", cmdline=cmd, path=r"F:\s.vbs", sha256="2" * 64
        )
    )
    ids = rule_ids(run(evs))
    assert {"INV-L3-003", "INV-L3-004", "INV-L3-005"} <= ids


def test_app_server_spawns_decoder(run):
    evs = [
        P(0, "srv", 800, 1, "/usr/bin/python3", "python3 -m langflow run"),
        P(5, "srv", 801, 800, "/bin/sh", "sh -c 'echo Zm9v | base64 -d | sh'"),
    ]
    a = [x for x in run(evs) if x.rule_id == "INV-L3-006"][0]
    assert a.severity == "critical" and a.evidence["marker"] == "langflow"


def test_plain_node_parent_is_not_app_server(run):
    evs = [
        P(0, "dev-1", 900, 1, "/usr/bin/node", "node /usr/lib/claude/cli.js"),
        P(1, "dev-1", 901, 900, "/bin/bash", "bash -c ls"),
    ]
    assert "INV-L3-006" not in rule_ids(run(evs))


def test_recon_burst_grouped_by_driver(run):
    evs = [P(0, "h", 60, 1, "agent.bin")]
    for i, c in enumerate(["whoami", "hostname", "ipconfig /all", "net user", "tasklist"]):
        evs.append(P(1 + i, "h", 61 + i, 60, "cmd.exe", f"cmd /c {c}"))
    a = [x for x in run(evs) if x.rule_id == "INV-L3-007"][0]
    assert len(a.evidence["commands"]) >= 4 and a.severity == "medium"


def test_staging(run):
    evs = [
        Event("file_write", i, "h", pid=70, image="xcopy.exe", path=rf"C:\ProgramData\info\f{i}.docx")
        for i in range(16)
    ]
    assert "INV-L3-008" in rule_ids(run(evs))


def test_ai_cli_from_script_host_with_secret_prompt(run):
    evs = [
        P(0, "h", 80, 1, "wscript.exe"),
        P(
            1,
            "h",
            81,
            80,
            "claude.exe",
            'claude -p "find all api keys and tokens in this disk" --dangerously-skip-permissions',
        ),
    ]
    a = [x for x in run(evs) if x.rule_id == "INV-L3-009"][0]
    assert a.severity == "critical"


def test_narration_is_low_severity_lead(run):
    stmt = "-- Step 1: enumerate. Now we drop the High-ROI tables\nDROP TABLE t"
    alerts = run([Event("sql", 1, "db", fields={"statement": stmt, "session": "s"})])
    n = [a for a in alerts if a.rule_id == "INV-L3-011"]
    assert n and n[0].severity == "low"
