# Running invariant-defense on macOS

Status: **beta**. Unit-tested on macOS in CI (Apple silicon) and against recorded eslogger
JSON; validate the eslogger field layout on your macOS version before relying on it (see
"Schema check" below).

## What you get on a Mac

| Layer | Telemetry on macOS | Coverage |
|---|---|---|
| L1 Exposure | inventory YAML (OS-independent) | full |
| L2 Model dependency | `psutil` connection sampling as root (`--net-interval`), AI gateway / proxy logs | partial: sampling misses short connections; Endpoint Security has no network events |
| L2 Hunting | `invariant hunt` on files, repos, `~/.claude`, `.mcp.json`, `.cursor/` | full |
| L3 Behavior | `eslogger` exec / create / close / rename / unlink | full set of L3 detectors, plus code-signing state |
| L4 Identity | IdP, gateway and app logs (OS-independent) | full |
| L5 Impact | `eslogger` rename / unlink / close, canaries, SQL guards, snapshots (`chflags uchg`) | rate, canary and SQL detectors; no entropy (ES does not see content) |
| Response | `pf` isolation (`isolate: pf` or `auto`), webhook to your EDR/MDM | full |

## 1. Install

```bash
python3 -m venv ~/.venvs/invariant && source ~/.venvs/invariant/bin/activate
pip install -e ".[live,yara]"        # from your clone of github.com/skbellevue/invariant-defense
pytest -o addopts="" -q
invariant demo --scenario s1ngularity --respond   # macOS replay, mapped through the eslogger collector
```

## 2. Grant Full Disk Access

`eslogger` (macOS 13 and later) must run as root, and the process responsible for it needs Full
Disk Access: Terminal or iTerm when you run it by hand, `/usr/bin/eslogger` itself when it runs as a
LaunchDaemon. On managed fleets grant it with an MDM PPPC profile (`SystemPolicyAllFiles`).

System Settings → Privacy & Security → Full Disk Access → add your terminal app.

## 3. Try it interactively

```bash
sudo eslogger exec create rename unlink close \
  | invariant stream --format eslogger --min-severity medium
```

Add network sampling for the L2 egress layer (psutil needs root on macOS to see other processes'
sockets; without it the tool now warns instead of failing silently):

```bash
sudo eslogger exec create rename unlink close \
  | sudo "$(which invariant)" stream --format eslogger --net-interval 5
```

Record and replay later:

```bash
sudo eslogger exec create rename unlink close > ~/es-$(date +%F).jsonl     # Ctrl-C to stop
invariant detect --format eslogger --events ~/es-2026-11-25.jsonl --json report.json
```

## 4. Run it as a LaunchDaemon

```bash
sudo mkdir -p "/Library/Application Support/Invariant" /var/log/invariant
sudo python3 -m venv "/Library/Application Support/Invariant/venv"
sudo "/Library/Application Support/Invariant/venv/bin/pip" install "/path/to/invariant-defense[live]"
sudo cp deploy/macos/invariant-eslogger.sh "/Library/Application Support/Invariant/"
sudo cp config/invariant.example.yaml "/Library/Application Support/Invariant/invariant.yaml"   # edit it
sudo cp deploy/macos/com.invariant.eslogger.plist /Library/LaunchDaemons/
sudo chown root:wheel /Library/LaunchDaemons/com.invariant.eslogger.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/com.invariant.eslogger.plist
tail -f /var/log/invariant/alerts.log
```

Stop it with `sudo launchctl bootout system/com.invariant.eslogger`.

## 5. Isolation with pf

Set the isolate adapter to `pf` (or `auto`, which picks `pf` on macOS and `iptables` on Linux):

```yaml
response:
  dry_run: false            # only after a tabletop exercise
  adapters: {isolate: auto}
  management_cidrs: [10.0.0.0/24]
```

The adapter loads these rules into the `com.apple/invariant` anchor, which the stock
`/etc/pf.conf` evaluates through its `anchor "com.apple/*"` line, then enables pf:

```
pass quick on lo0 all
pass out quick to 10.0.0.0/24 keep state
pass in quick from 10.0.0.0/24 keep state
block drop quick all
```

Undo: `sudo invariant unisolate --adapter pf --execute` (flushes the anchor). On managed
fleets prefer your EDR's or MDM's containment API through the `webhook` adapter: it survives
reboots and is visible to the rest of the SOC.

## 6. Immutable snapshots

```bash
invariant snapshot create /path/to/config-exports --dest /Volumes/Backup/invariant --immutable
```

On macOS `--immutable` sets the user-immutable flag (`chflags uchg`); remove it with
`chflags -R nouchg <snapshot>`. For stronger guarantees use `schg` as root (cleared only in
single-user mode) or WORM storage.

## Schema check

Apple documents `eslogger` output as modeled on `es_message_t`, with no schema guarantee across
releases. The collector is tolerant (it keys on the event name, accepts both destination-union
shapes and bare paths) but check once per macOS major release:

```bash
sudo eslogger exec create rename unlink close | head -n 50 > /tmp/es-sample.jsonl
invariant detect --format eslogger --events /tmp/es-sample.jsonl --min-severity info
python3 -c "import json;[print(json.loads(l)['event'].keys()) for l in open('/tmp/es-sample.jsonl')]"
```

If paths or pids come out empty, open an issue with a redacted sample line.

## Known limits

* **No network events from Endpoint Security.** Use `--net-interval` sampling, AI-gateway logs, or a
  Network Extension content filter that writes `network_connect` JSONL (planned).
* **Volume.** `close` and `create` are busy on developer machines. If needed, pre-filter with
  `jq` (for example drop `/private/var/folders/` and `~/Library/Caches/`) before `invariant stream`.
* **`write` events** fire per write call; the default pipeline uses `close` with `modified: true`.
* **Entropy** is not available from ES, so L5-002 counts renames and deletes only on macOS.
