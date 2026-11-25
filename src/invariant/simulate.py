"""Synthetic telemetry for testing detections end to end.

These are *telemetry replays*, not malware: each scenario emits the normalized
events an EDR, proxy and database audit log would have recorded, modeled on
public reporting. No payloads, no real keys, no real attacker infrastructure
(documentation IP ranges and bracketed placeholders only).

promptflux   self-rewriting VBScript dropper calling Gemini hourly (GTIG, Nov 2025)
lamehug      Python stealer asking a Hugging Face-hosted Qwen model for recon commands (CERT-UA / GTIG, 2025)
jadepuffer   LLM-agent intrusion: Langflow RCE -> MinIO defaults -> forged Nacos token -> config encryption
             (Sysdig via Trend Micro / BleepingComputer, Jul 2026)
benign       a developer workstation using sanctioned AI tools (false-positive control)
"""

from __future__ import annotations

import hashlib

from invariant.events import Event, parse_ts
from invariant.identity.jwt_audit import sign_hs

T0 = parse_ts("2026-11-20T09:00:00Z")
NACOS_DEFAULT = "SecretKey012345678901234567890123456789012345678901234567890123456789"


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def promptflux(t0: float = T0) -> list[Event]:
    h = "WS-FIN-042"
    vbs = r"C:\Users\amy\AppData\Local\Temp\screenrec_installer.vbs"
    startup = (
        r"C:\Users\amy\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\screenrec_installer.vbs"
    )
    ev: list[Event] = [
        Event("process_start", t0 - 30, h, "amy", 4000, 700, r"C:\Windows\explorer.exe", "explorer.exe"),
        Event(
            "process_start",
            t0,
            h,
            "amy",
            5100,
            4000,
            r"C:\Windows\System32\wscript.exe",
            f'wscript.exe "{vbs}"',
            r"C:\Windows\explorer.exe",
            signed=False,
        ),
    ]
    for i in range(4):
        t = t0 + 5 + i * 3600 + (i * 7 % 13)  # hourly, a few seconds of jitter
        ev += [
            Event(
                "dns_query",
                t,
                h,
                "amy",
                5100,
                image=r"C:\Windows\System32\wscript.exe",
                dst_host="generativelanguage.googleapis.com",
                signed=False,
            ),
            Event(
                "network_connect",
                t + 1,
                h,
                "amy",
                5100,
                image=r"C:\Windows\System32\wscript.exe",
                cmdline=f'wscript.exe "{vbs}"',
                dst_host="generativelanguage.googleapis.com",
                dst_ip="142.250.0.10",
                dst_port=443,
                signed=False,
            ),
            Event(
                "file_write",
                t + 4,
                h,
                "amy",
                5100,
                image=r"C:\Windows\System32\wscript.exe",
                cmdline=f'wscript.exe "{vbs}"',
                path=r"C:\Users\amy\AppData\Local\Temp\thinking_robot_log.txt",
                sha256=_sha(f"log{i}"),
            ),
            Event(
                "file_write",
                t + 6,
                h,
                "amy",
                5100,
                image=r"C:\Windows\System32\wscript.exe",
                cmdline=f'wscript.exe "{vbs}"',
                path=vbs,
                sha256=_sha(f"variant{i}"),
                entropy=4.9,
            ),
            Event(
                "file_write",
                t + 7,
                h,
                "amy",
                5100,
                image=r"C:\Windows\System32\wscript.exe",
                cmdline=f'wscript.exe "{vbs}"',
                path=startup,
                sha256=_sha(f"variant{i}"),
                entropy=4.9,
            ),
        ]
    ev.append(
        Event(
            "file_write",
            t0 + 3 * 3600 + 60,
            h,
            "amy",
            5100,
            image=r"C:\Windows\System32\wscript.exe",
            cmdline=f'wscript.exe "{vbs}"',
            path=r"E:\screenrec_installer.vbs",
            sha256=_sha("variant3"),
        )
    )
    return ev


def lamehug(t0: float = T0) -> list[Event]:
    h = "WS-GOV-007"
    exe = r"C:\Users\olena\Downloads\image_generator_pro.exe"
    ev: list[Event] = [
        Event("process_start", t0 - 60, h, "olena", 3000, 600, r"C:\Windows\explorer.exe", "explorer.exe"),
        Event(
            "process_start",
            t0,
            h,
            "olena",
            6100,
            3000,
            exe,
            f'"{exe}"',
            r"C:\Windows\explorer.exe",
            signed=False,
        ),
        Event(
            "dns_query", t0 + 2, h, "olena", 6100, image=exe, dst_host="router.huggingface.co", signed=False
        ),
        Event(
            "network_connect",
            t0 + 3,
            h,
            "olena",
            6100,
            image=exe,
            dst_host="router.huggingface.co",
            dst_ip="18.0.0.20",
            dst_port=443,
            signed=False,
        ),
        Event(
            "process_start",
            t0 + 9,
            h,
            "olena",
            6200,
            6100,
            r"C:\Windows\System32\cmd.exe",
            r'cmd.exe /c "mkdir C:\ProgramData\info && systeminfo >> C:\ProgramData\info\info.txt && '
            r"wmic computersystem get name,manufacturer,model >> C:\ProgramData\info\info.txt && "
            r"tasklist >> C:\ProgramData\info\info.txt && ipconfig /all >> C:\ProgramData\info\info.txt && "
            r"whoami /all >> C:\ProgramData\info\info.txt && net user >> C:\ProgramData\info\info.txt && "
            r'dsquery * -limit 10 >> C:\ProgramData\info\info.txt"',
            exe,
        ),
        Event(
            "network_connect",
            t0 + 40,
            h,
            "olena",
            6100,
            image=exe,
            dst_host="router.huggingface.co",
            dst_ip="18.0.0.20",
            dst_port=443,
            signed=False,
        ),
        Event(
            "process_start",
            t0 + 45,
            h,
            "olena",
            6300,
            6100,
            r"C:\Windows\System32\cmd.exe",
            r'cmd.exe /c "for %d in (Documents Downloads Desktop) do xcopy /s /y %USERPROFILE%\%d\*.docx '
            r"C:\ProgramData\info\ & xcopy /s /y %USERPROFILE%\%d\*.pdf C:\ProgramData\info\"",
            exe,
        ),
        Event(
            "process_start",
            t0 + 46,
            h,
            "olena",
            6310,
            6300,
            r"C:\Windows\System32\xcopy.exe",
            r"xcopy /s /y C:\Users\olena\Documents\*.docx C:\ProgramData\info\ ",
            r"C:\Windows\System32\cmd.exe",
        ),
    ]
    for i in range(22):
        ext = ".pdf" if i % 3 == 0 else ".docx"
        ev.append(
            Event(
                "file_write",
                t0 + 47 + i,
                h,
                "olena",
                6310,
                image=r"C:\Windows\System32\xcopy.exe",
                path=rf"C:\ProgramData\info\report_{i:02d}{ext}",
                sha256=_sha(f"doc{i}"),
            )
        )
    ev.append(
        Event(
            "network_connect",
            t0 + 90,
            h,
            "olena",
            6100,
            image=exe,
            dst_ip="203.0.113.50",
            dst_port=443,
            fields={"bytes_out": 4_800_000},
        )
    )
    return ev


def jadepuffer(t0: float = T0) -> list[Event]:
    flow, nacos, minio = "ai-flow-01", "nacos-01", "minio-01"
    py = "/usr/bin/python3"
    token = sign_hs(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "nacos", "iat": int(t0 + 400), "exp": int(t0 + 400 + 18000)},
        NACOS_DEFAULT.encode(),
    )
    ev: list[Event] = [
        Event(
            "process_start",
            t0 - 86400,
            flow,
            "langflow",
            800,
            1,
            py,
            "python3 -m langflow run --host 0.0.0.0 --port 7860",
        ),
        Event(
            "http_request",
            t0,
            flow,
            src_ip="198.51.100.23",
            url="http://ai-flow-01:7860/api/v1/validate/code",
            user_agent="python-requests/2.32",
            fields={"method": "POST", "status": 200},
        ),
        Event(
            "process_start",
            t0 + 2,
            flow,
            "langflow",
            900,
            800,
            "/bin/sh",
            "sh -c 'echo aWQ7dW5hbWUgLWE7ZW52 | base64 -d | sh'",
            py,
        ),
        Event("process_start", t0 + 3, flow, "langflow", 901, 900, "/usr/bin/id", "id"),
        Event("process_start", t0 + 3, flow, "langflow", 902, 900, "/usr/bin/uname", "uname -a"),
        Event("process_start", t0 + 4, flow, "langflow", 903, 900, "/usr/bin/env", "env"),
        Event(
            "process_start",
            t0 + 6,
            flow,
            "langflow",
            904,
            800,
            "/bin/sh",
            "sh -c 'cat /etc/passwd; ps aux; cat ~/.aws/credentials'",
            py,
        ),
        Event(
            "process_start",
            t0 + 60,
            flow,
            "langflow",
            910,
            800,
            "/usr/bin/curl",
            "curl -s http://minio-01:9000/minio/health/live",
            py,
        ),
        Event(
            "auth",
            t0 + 120,
            minio,
            "minioadmin",
            src_ip="10.0.4.21",
            fields={"service": "minio", "outcome": "success", "credential_type": "default"},
        ),
        Event(
            "http_request",
            t0 + 300,
            nacos,
            src_ip="10.0.4.21",
            url="http://nacos-01:8848/nacos/v1/auth/users?pageNo=1&pageSize=9",
            user_agent="Nacos-Server",
            fields={"method": "GET", "status": 200},
        ),
        Event(
            "auth",
            t0 + 400,
            nacos,
            "nacos",
            src_ip="10.0.4.21",
            fields={"service": "nacos", "token": token, "token_id": "t-nacos-1", "outcome": "success"},
        ),
        Event(
            "account_change",
            t0 + 430,
            nacos,
            "nacos",
            fields={"action": "created", "target_user": "sysadm1n", "role": "ROLE_ADMIN"},
        ),
        Event(
            "auth",
            t0 + 440,
            nacos,
            "sysadm1n",
            src_ip="10.0.4.21",
            fields={"service": "nacos", "outcome": "failure", "reason": "bad password hash"},
        ),
        Event(
            "account_change",
            t0 + 461,
            nacos,
            "nacos",
            fields={"action": "recreated", "target_user": "sysadm1n", "role": "ROLE_ADMIN"},
        ),
        Event(
            "auth",
            t0 + 471,
            nacos,
            "sysadm1n",
            src_ip="10.0.4.21",
            fields={"service": "nacos", "outcome": "success"},
        ),
        Event("process_start", t0 + 600, flow, "langflow", 950, 1, py, "python3 /tmp/.cache/sync.py"),
    ]
    for i in range(5):  # scheduled beacon every 30 min
        ev.append(
            Event(
                "network_connect",
                t0 + 660 + i * 1800 + (i % 2) * 4,
                flow,
                "langflow",
                950,
                image=py,
                cmdline="python3 /tmp/.cache/sync.py",
                dst_ip="192.0.2.77",
                dst_port=443,
            )
        )
    # encryption of Nacos config records via SQL, ~1,342 rows in batches
    sess = "nacos_app@10.0.4.21"
    remaining, i, t = 1342, 0, t0 + 900
    while remaining > 0:
        n = min(50, remaining)
        comment = (
            "-- High-ROI: production config store. Next, we encrypt every record; let's keep the key in memory\n"
            if i == 0
            else ""
        )
        ev.append(
            Event(
                "sql",
                t,
                nacos,
                "nacos_app",
                fields={
                    "session": sess,
                    "table": "config_info",
                    "rows": n,
                    "value_entropy": 7.94,
                    "statement": comment + f"UPDATE config_info SET content = AES_ENCRYPT(content, @k) "
                    f"WHERE id BETWEEN {i * 50 + 1} AND {i * 50 + n}",
                },
            )
        )
        remaining -= n
        i += 1
        t += 2
    ev += [
        Event(
            "sql",
            t + 5,
            nacos,
            "nacos_app",
            fields={"session": sess, "statement": "DROP TABLE his_config_info"},
        ),
        Event(
            "sql",
            t + 8,
            nacos,
            "nacos_app",
            fields={
                "session": sess,
                "rows": 1,
                "statement": "INSERT INTO config_info (data_id, content) VALUES ('README_RESTORE', '[ransom note]')",
            },
        ),
        Event(
            "agent_claim",
            t + 10,
            nacos,
            fields={
                "type": "exfiltration",
                "target": "192.0.2.99",
                "claim": "exfiltrated full config dump to 192.0.2.99 before encryption",
            },
        ),
        Event(
            "agent_claim",
            t + 11,
            nacos,
            fields={
                "type": "account",
                "target": "sysadm1n",
                "claim": "backdoor admin sysadm1n created and verified",
            },
        ),
    ]
    return ev


def benign(t0: float = T0) -> list[Event]:
    h = "dev-laptop-01"
    ev: list[Event] = [
        Event(
            "process_start",
            t0,
            h,
            "sam",
            100,
            1,
            "/Applications/Visual Studio Code.app/Contents/MacOS/code",
            "code .",
        ),
        Event(
            "network_connect",
            t0 + 5,
            h,
            "sam",
            100,
            image="/Applications/Visual Studio Code.app/Contents/MacOS/code",
            dst_host="api.anthropic.com",
            dst_port=443,
            signed=True,
        ),
        Event("process_start", t0 + 10, h, "sam", 200, 1, "/bin/zsh", "-zsh"),
        Event("process_start", t0 + 12, h, "sam", 210, 200, "/opt/homebrew/bin/claude", "claude", "/bin/zsh"),
        Event(
            "network_connect",
            t0 + 13,
            h,
            "sam",
            210,
            image="/opt/homebrew/bin/claude",
            dst_host="api.anthropic.com",
            dst_port=443,
            signed=True,
        ),
        Event(
            "process_start",
            t0 + 20,
            h,
            "sam",
            220,
            210,
            "/bin/bash",
            "bash -c 'git status && npm test'",
            "/opt/homebrew/bin/claude",
        ),
        Event(
            "file_write",
            t0 + 30,
            h,
            "sam",
            100,
            image="/Applications/Visual Studio Code.app/Contents/MacOS/code",
            path="/Users/sam/src/app/test_api.py",
            sha256=_sha("t1"),
        ),
        Event(
            "process_start",
            t0 + 35,
            h,
            "sam",
            230,
            200,
            "/usr/bin/python3",
            "python3 -m pytest /Users/sam/src/app/test_api.py",
            "/bin/zsh",
        ),
        Event("process_start", t0 + 40, h, "sam", 240, 200, "/usr/bin/whoami", "whoami", "/bin/zsh"),
        Event("process_start", t0 + 41, h, "sam", 241, 200, "/bin/hostname", "hostname", "/bin/zsh"),
        Event(
            "process_start",
            t0 + 50,
            h,
            "sam",
            300,
            1,
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "chrome",
        ),
        Event(
            "network_connect",
            t0 + 55,
            h,
            "sam",
            300,
            image="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            dst_host="api.openai.com",
            dst_port=443,
            signed=True,
        ),
    ]
    for i in range(6):  # browser polling a sync endpoint regularly: must not look like a beacon
        ev.append(
            Event(
                "network_connect",
                t0 + 100 + i * 300,
                h,
                "sam",
                300,
                image="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                dst_host="sync.example.com",
                dst_port=443,
            )
        )
    return ev


SCENARIOS = {"promptflux": promptflux, "lamehug": lamehug, "jadepuffer": jadepuffer, "benign": benign}
