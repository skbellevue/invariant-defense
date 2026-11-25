"""L3 detectors: detect techniques, not files.

INV-L3-001  model reply executed: a process that just queried an LLM spawned a shell/interpreter
INV-L3-002  generated script executed: a script written moments ago was launched
INV-L3-003  self-rewriting script: one file rewritten into several distinct versions
INV-L3-004  persistence: script/binary dropped into an autostart location
INV-L3-005  removable-media / share propagation of a script
INV-L3-006  application server spawned a shell, downloader or decoder
INV-L3-007  reconnaissance burst from one process tree
INV-L3-008  document staging into a single directory
INV-L3-009  AI command-line tool driven by an unexpected parent or with secret-hunting prompts
INV-L3-011  LLM-agent narration inside a command (weak signal, a lead to verify)
"""

from __future__ import annotations

import os
import re
from collections import defaultdict, deque

from invariant.alerts import Alert
from invariant.config import Config
from invariant.engine import Context, Detector
from invariant.events import Event
from invariant.util import glob_any, norm_path, squash


def _ext(path: str | None) -> str:
    return os.path.splitext(norm_path(path))[1]


def _dirname(path: str | None) -> str:
    return norm_path(path).rsplit("/", 1)[0]


def _word_rx(term: str) -> re.Pattern[str]:
    return re.compile(r"(?<![\w.-])" + re.escape(term.lower()) + r"(?![\w-])")


class _Base(Detector):
    layer = "L3"

    def __init__(self, config: Config):
        self.cfg = config.section("behavior")
        self.shells = self.cfg.get("shells", [])
        self.script_ext = set(self.cfg.get("script_extensions", []))
        self.dev_tools = self.cfg.get("dev_tools", [])

    def is_shell(self, name: str) -> bool:
        return glob_any(name, self.shells)


# --------------------------------------------------------------------- 001
class QueryThenExecDetector(_Base):
    name = "query-then-exec"

    def __init__(self, config: Config):
        super().__init__(config)
        self.window = float(self.cfg.get("query_then_exec_window_s", 300))

    def process(self, ev: Event, ctx: Context) -> list[Alert]:
        if ev.kind != "process_start" or not self.is_shell(ev.image_name):
            return []
        contact = ctx.recent_llm_contact(ev.host, ev.ppid, ev.ts, self.window)
        if not contact:
            return []
        requester = os.path.basename(norm_path(contact.image)) or "?"
        return [
            Alert(
                "INV-L3-001",
                f"'{requester}' queried {contact.provider} then spawned '{ev.image_name}'",
                "critical",
                "L3",
                ev.host,
                ev.ts,
                "A process outside the AI allow-list asked a language model for output and, "
                f"{ev.ts - contact.ts:.0f}s later, launched an interpreter. This is the just-in-time "
                "pattern of LAMEHUG/PROMPTSTEAL and PromptLock: the code is new every time, the sequence is not.",
                ["T1059", "T1027.014", "T1071.001"],
                {
                    "provider": contact.provider,
                    "requester_pid": contact.pid,
                    "seconds_after_query": round(ev.ts - contact.ts, 1),
                    "process_chain": ctx.tree.chain(ev.host, ev.pid),
                    "cmdline": squash(ev.cmdline),
                    "dedupe_key": f"{contact.pid}|{ev.image_name}",
                },
                [ev],
            )
        ]


# --------------------------------------------------------------------- 002 / 003 / 004 / 005
class ScriptLifecycleDetector(_Base):
    """Tracks scripts from write to execution, rewrite, persistence and spread."""

    name = "script-lifecycle"

    def __init__(self, config: Config):
        super().__init__(config)
        self.exec_window = float(self.cfg.get("generated_script_window_s", 600))
        self.min_versions = int(self.cfg.get("self_rewrite_min_versions", 3))
        self.q_window = float(self.cfg.get("query_then_exec_window_s", 300)) * 12  # regeneration can be slow
        self.persist = self.cfg.get("persistence_paths", [])
        self.removable = self.cfg.get("removable_paths", [])
        # (host, path) -> (ts, writer pid, writer image)
        self.recent: dict[tuple[str, str], tuple[float, int | None, str]] = {}
        # (host, path) -> set of hashes
        self.versions: dict[tuple[str, str], set[str]] = defaultdict(set)
        # (host, sha) -> first path seen
        self.sha_paths: dict[tuple[str, str], str] = {}

    def _writer_contact(self, ev: Event, ctx: Context):
        return ctx.recent_llm_contact(ev.host, ev.pid, ev.ts, self.q_window)

    def process(self, ev: Event, ctx: Context) -> list[Alert]:
        if ev.kind == "file_write":
            return self._on_write(ev, ctx)
        if ev.kind == "process_start":
            return self._on_exec(ev, ctx)
        return []

    def _on_write(self, ev: Event, ctx: Context) -> list[Alert]:
        path = norm_path(ev.path)
        ext = _ext(path)
        is_script = ext in self.script_ext
        out: list[Alert] = []
        writer = ev.image_name
        if is_script:
            self.recent[(ev.host, path)] = (ev.ts, ev.pid, writer)
            # bound memory
            if len(self.recent) > 50_000:
                for k in list(self.recent)[:10_000]:
                    self.recent.pop(k, None)
        contact = self._writer_contact(ev, ctx)

        # 003 self-rewrite
        if is_script and ev.sha256:
            vs = self.versions[(ev.host, path)]
            vs.add(ev.sha256)
            base = os.path.basename(path)
            self_ref = base and base in norm_path(ev.cmdline)
            if len(vs) >= self.min_versions and (self_ref or contact):
                out.append(
                    Alert(
                        "INV-L3-003",
                        f"Script rewritten into {len(vs)} distinct versions: {os.path.basename(path)}",
                        "critical" if contact else "high",
                        "L3",
                        ev.host,
                        ev.ts,
                        "Every version has a different hash, so every version defeats a hash or byte signature. "
                        "The invariant is the rewrite itself"
                        + (f", fed by calls to {contact.provider}." if contact else "."),
                        ["T1027.014"],
                        {
                            "path": ev.path,
                            "versions": len(vs),
                            "writer": writer,
                            "self_referencing": bool(self_ref),
                            "provider": contact.provider if contact else None,
                            "dedupe_key": path,
                        },
                        [ev],
                    )
                )
            if ev.sha256 and (ev.host, ev.sha256) not in self.sha_paths:
                self.sha_paths[(ev.host, ev.sha256)] = path

        # 004 persistence
        if glob_any(path, self.persist) and (
            is_script or ext in (".exe", ".dll", ".lnk", ".plist", ".service", "")
        ):
            sev = "high" if (contact or self.is_shell(writer)) else "medium"
            if contact:
                sev = "critical"
            out.append(
                Alert(
                    "INV-L3-004",
                    f"Autostart persistence written by '{writer}': {os.path.basename(path)}",
                    sev,
                    "L3",
                    ev.host,
                    ev.ts,
                    "A file was placed where the OS will run it at logon/boot. PROMPTFLUX copied each regenerated "
                    "script into the Startup folder.",
                    ["T1547.001"] if "startup" in path else ["T1053", "T1547.001"],
                    {
                        "path": ev.path,
                        "writer": writer,
                        "process_chain": ctx.tree.chain(ev.host, ev.pid),
                        "provider": contact.provider if contact else None,
                        "dedupe_key": path,
                    },
                    [ev],
                )
            )

        # 005 propagation
        if is_script and glob_any(path, self.removable) and writer not in ("explorer.exe", "finder"):
            first = self.sha_paths.get((ev.host, ev.sha256 or ""), path)
            out.append(
                Alert(
                    "INV-L3-005",
                    f"Script copied to removable media or share by '{writer}'",
                    "high",
                    "L3",
                    ev.host,
                    ev.ts,
                    "Script hosts copying themselves to removable drives or mapped shares is worm behavior.",
                    ["T1091"],
                    {
                        "path": ev.path,
                        "same_content_as": first if first != path else None,
                        "writer": writer,
                        "dedupe_key": path,
                    },
                    [ev],
                )
            )
        return out

    def _on_exec(self, ev: Event, ctx: Context) -> list[Alert]:
        cmd = norm_path(ev.cmdline)
        if not cmd:
            return []
        out: list[Alert] = []
        for (host, path), (wts, wpid, wimage) in list(self.recent.items()):
            if host != ev.host or not (0 <= ev.ts - wts <= self.exec_window):
                continue
            if path not in cmd:
                continue
            if glob_any(wimage, self.dev_tools):
                continue
            wev = Event("file_write", ts=wts, host=host, pid=wpid, image=wimage)
            contact = ctx.recent_llm_contact(host, wpid, wts, self.q_window)
            out.append(
                Alert(
                    "INV-L3-002",
                    f"Freshly written script executed {ev.ts - wts:.0f}s after '{wimage}' wrote it",
                    "critical" if contact else "high",
                    "L3",
                    ev.host,
                    ev.ts,
                    "A script that did not exist minutes ago was run. Legitimate software ships its scripts; "
                    "generated-code malware writes and runs them on the fly.",
                    ["T1059", "T1027.014"],
                    {
                        "script": path,
                        "writer": wimage,
                        "runner": ev.image_name,
                        "provider": contact.provider if contact else None,
                        "process_chain": ctx.tree.chain(ev.host, ev.pid),
                        "dedupe_key": path,
                    },
                    [wev, ev],
                )
            )
        return out


# --------------------------------------------------------------------- 006
class AppServerShellDetector(_Base):
    name = "app-server-shell"
    _decode = re.compile(
        r"base64\s+(-d|--decode)|frombase64string|certutil.+-decode|\|\s*(ba)?sh\b|curl[^|]*\|\s*\w*sh|wget[^|]*\|\s*\w*sh",
        re.I,
    )

    def __init__(self, config: Config):
        super().__init__(config)
        app = self.cfg.get("app_servers", {})
        self.images = app.get("images", [])
        self.markers = [m.lower() for m in app.get("cmdline_markers", [])]
        self.children = self.cfg.get("app_server_children", [])

    def _is_app_server(self, image: str, cmdline: str) -> str | None:
        name = image.replace("\\", "/").rsplit("/", 1)[-1].lower()
        cl = cmdline.lower()
        # Generic runtimes (java, python, node) are recognized by what they run...
        for m in self.markers:
            if m in cl or m in name:
                return m
        # ...dedicated server binaries by name alone.
        if glob_any(name, self.images):
            return name
        return None

    def process(self, ev: Event, ctx: Context) -> list[Alert]:
        if ev.kind != "process_start" or not glob_any(ev.image_name, self.children):
            return []
        parent = ctx.tree.get(ev.host, ev.ppid)
        p_image = parent.image if parent else (ev.parent_image or "")
        p_cmd = parent.cmdline if parent else ""
        marker = self._is_app_server(p_image, p_cmd)
        if not marker:
            return []
        decoding = bool(self._decode.search(ev.cmdline or ""))
        return [
            Alert(
                "INV-L3-006",
                f"Application server ({marker}) spawned '{ev.image_name}'"
                + (" with decode/pipe-to-shell" if decoding else ""),
                "critical" if decoding else "high",
                "L3",
                ev.host,
                ev.ts,
                "Web/automation servers should not start shells, downloaders or decoders. This is what "
                "exploitation of an AI platform looks like from the host (JADEPUFFER entered through Langflow "
                "CVE-2025-3248).",
                ["T1190", "T1059", "T1140"] if decoding else ["T1190", "T1059"],
                {
                    "parent": p_image,
                    "marker": marker,
                    "cmdline": squash(ev.cmdline),
                    "process_chain": ctx.tree.chain(ev.host, ev.pid),
                    "dedupe_key": f"{marker}|{ev.image_name}|{decoding}",
                },
                [ev],
            )
        ]


# --------------------------------------------------------------------- 007
class ReconBurstDetector(_Base):
    name = "recon-burst"

    def __init__(self, config: Config):
        super().__init__(config)
        self.window = float(self.cfg.get("recon_window_s", 120))
        self.min_distinct = int(self.cfg.get("recon_min_distinct", 4))
        self.cmds = [(c, _word_rx(c)) for c in self.cfg.get("recon_commands", [])]
        self.hits: dict[tuple[str, int], deque[tuple[float, str]]] = defaultdict(deque)
        self.q_window = float(self.cfg.get("query_then_exec_window_s", 300))
        self.command_shells = self.cfg.get("command_shells", [])

    def _root(self, ev: Event, ctx: Context) -> int:
        """Nearest ancestor that is not itself a shell: the thing driving the commands."""
        for p in ctx.tree.ancestors(ev.host, ev.pid):
            if not glob_any(p.name, self.command_shells):
                return p.pid
        return ev.ppid or ev.pid or -1

    def process(self, ev: Event, ctx: Context) -> list[Alert]:
        if ev.kind != "process_start" or not ev.cmdline:
            return []
        cl = ev.cmdline.lower()
        found = [c for c, rx in self.cmds if rx.search(cl)]
        if not found:
            return []
        root = self._root(ev, ctx)
        dq = self.hits[(ev.host, root)]
        for c in found:
            dq.append((ev.ts, c))
        while dq and ev.ts - dq[0][0] > self.window:
            dq.popleft()
        distinct = sorted({c for _, c in dq})
        if len(distinct) < self.min_distinct:
            return []
        contact = ctx.recent_llm_contact(ev.host, root, ev.ts, self.q_window * 4)
        root_proc = ctx.tree.get(ev.host, root)
        return [
            Alert(
                "INV-L3-007",
                f"Reconnaissance burst ({len(distinct)} discovery commands) from '{root_proc.name if root_proc else root}'",
                "critical" if contact else "medium",
                "L3",
                ev.host,
                ev.ts,
                "Many discovery commands from one process tree in a short window. When the driver also talks to "
                "a model, the commands were likely generated (LAMEHUG asked Qwen for one-line recon commands).",
                ["T1082", "T1016", "T1033", "T1057"],
                {
                    "commands": distinct,
                    "driver": root_proc.image if root_proc else None,
                    "provider": contact.provider if contact else None,
                    "dedupe_key": str(root),
                },
                [ev],
            )
        ]


# --------------------------------------------------------------------- 008
class StagingDetector(_Base):
    name = "staging"

    def __init__(self, config: Config):
        super().__init__(config)
        self.window = float(self.cfg.get("staging_window_s", 600))
        self.min_files = int(self.cfg.get("staging_min_files", 15))
        self.doc_ext = set(self.cfg.get("document_extensions", []))
        self.writes: dict[tuple[str, str], deque[tuple[float, str, int | None]]] = defaultdict(deque)

    def process(self, ev: Event, ctx: Context) -> list[Alert]:
        if ev.kind != "file_write" or _ext(ev.path) not in self.doc_ext:
            return []
        if glob_any(ev.image_name, self.dev_tools) or ev.image_name in (
            "explorer.exe",
            "finder",
            "onedrive.exe",
            "dropbox",
        ):
            return []
        d = _dirname(ev.path)
        dq = self.writes[(ev.host, d)]
        dq.append((ev.ts, norm_path(ev.path), ev.pid))
        while dq and ev.ts - dq[0][0] > self.window:
            dq.popleft()
        files = {p for _, p, _ in dq}
        if len(files) < self.min_files:
            return []
        contact = ctx.recent_llm_contact(ev.host, ev.pid, ev.ts, 3600)
        return [
            Alert(
                "INV-L3-008",
                f"{len(files)} documents staged into {d}",
                "high" if contact else "medium",
                "L3",
                ev.host,
                ev.ts,
                "Bulk copying of office/PDF/text files into one directory precedes exfiltration "
                "(LAMEHUG staged into C:\\ProgramData\\info).",
                ["T1074.001"],
                {
                    "directory": d,
                    "files": len(files),
                    "writer": ev.image_name,
                    "provider": contact.provider if contact else None,
                    "dedupe_key": d,
                },
                [ev],
            )
        ]


# --------------------------------------------------------------------- 009
class AiCliAbuseDetector(_Base):
    name = "ai-cli-abuse"
    _risky_flags = re.compile(
        r"--dangerously-skip-permissions|--yolo|--full-auto|bypasspermissions|--allow-all-tools", re.I
    )
    _secret_hunt = re.compile(
        r"\b(api[_ -]?keys?|tokens?|passwords?|secrets?|credentials?|wallets?|seed phrase|private keys?|\.env|id_rsa|\.npmrc|\.aws)\b",
        re.I,
    )

    def __init__(self, config: Config):
        super().__init__(config)
        self.clis = self.cfg.get("ai_clis", [])
        self.parents = self.cfg.get("ai_cli_expected_parents", [])

    def process(self, ev: Event, ctx: Context) -> list[Alert]:
        if ev.kind != "process_start" or not glob_any(ev.image_name, self.clis):
            return []
        parent = ctx.tree.get(ev.host, ev.ppid)
        pname = parent.name if parent else ev.parent_name
        unexpected_parent = bool(pname) and not glob_any(pname, self.parents)
        risky = bool(self._risky_flags.search(ev.cmdline or ""))
        hunting = bool(self._secret_hunt.search(ev.cmdline or ""))
        if not (unexpected_parent or (risky and hunting)):
            return []
        sev = "critical" if (risky and hunting) or (unexpected_parent and hunting) else "high"
        return [
            Alert(
                "INV-L3-009",
                f"AI CLI '{ev.image_name}' launched by '{pname or '?'}'"
                + (" with secret-hunting prompt" if hunting else ""),
                sev,
                "L3",
                ev.host,
                ev.ts,
                "Locally installed AI coding agents are powerful, trusted tools. Malware can drive them to search "
                "for secrets (QUIETVAULT used on-host AI CLIs and a prompt to find more credentials).",
                ["T1059", "T1552.001"],
                {
                    "parent": pname,
                    "risky_flags": risky,
                    "secret_terms": hunting,
                    "cmdline": squash(ev.cmdline),
                    "dedupe_key": f"{pname}|{ev.image_name}",
                },
                [ev],
            )
        ]


# --------------------------------------------------------------------- 011
class NarrationDetector(_Base):
    name = "agent-narration"

    def __init__(self, config: Config):
        super().__init__(config)
        self.markers = [m.lower() for m in self.cfg.get("narration_markers", [])]

    def process(self, ev: Event, ctx: Context) -> list[Alert]:
        text = ""
        if ev.kind == "process_start" and self.is_shell(ev.image_name):
            text = ev.cmdline or ""
        elif ev.kind == "file_write":
            text = str(ev.fields.get("content_preview", ""))
        elif ev.kind == "sql":
            text = str(ev.fields.get("statement", ""))
        if len(text) < 40:
            return []
        tl = text.lower()
        hits = [m for m in self.markers if m in tl]
        if len(hits) < 2:
            return []
        return [
            Alert(
                "INV-L3-011",
                "Natural-language agent narration embedded in a payload",
                "low",
                "L3",
                ev.host,
                ev.ts,
                "Payloads that explain themselves in plain language are typical of LLM agents (JADEPUFFER tagged "
                "a database 'High-ROI' in a comment). Weak signal: a lead to correlate, never a verdict. Do not trust "
                "what the narration claims; verify against telemetry.",
                ["T1059"],
                {"markers": hits, "excerpt": squash(text, 160), "dedupe_key": ",".join(hits) + ev.kind},
                [ev],
            )
        ]


def behavior_detectors(config: Config) -> list[Detector]:
    return [
        QueryThenExecDetector(config),
        ScriptLifecycleDetector(config),
        AppServerShellDetector(config),
        ReconBurstDetector(config),
        StagingDetector(config),
        AiCliAbuseDetector(config),
        NarrationDetector(config),
    ]
