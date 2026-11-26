# macOS Network Extension: process-attributed network telemetry

Endpoint Security (the `eslogger` collector) sees processes and files but has no network
events. The L2 invariant, "AI-enabled malware must reach a model", needs to know *which
process* opened *which connection*. On macOS the supported way to get that is a
content-filter Network Extension. `macos/InvariantNetFilter` is one, built for this platform.

Status: **beta**. The shared Swift core is unit-tested on macOS and Linux; the extension
and host app build unsigned in CI. Running it requires your own Developer ID signing,
notarization and a Network Extension entitlement on your team.

## What it does

* A system extension (`NEFilterDataProvider`) sees every outbound TCP/UDP socket flow.
* For each flow it records pid, ppid, executable path, signing id, Team ID, platform-binary
  flag and a `signed` verdict (false for invalid or ad-hoc signatures, the usual state of
  dropped malware), plus destination IP, port and hostname when macOS provides one.
* It writes one record per flow, already in invariant's `network_connect` schema, to the
  unified log (`subsystem com.skbellevue.invariant.netfilter`) and to a rotated JSONL
  file in its app-group container.
* It is **monitor-only**: every verdict is `allow`. A crash or bug cannot cut the Mac off the
  network. Containment stays with the response loop (`pf`, EDR or MDM).

```
NEFilterSocketFlow ──► FilterDataProvider ──► FlowRecord (InvariantFlowCore)
  sourceProcessAuditToken  │  pid/euid from audit token          │
  remoteFlowEndpoint       │  proc_pidpath, proc_pidinfo (ppid)  ├─► unified log  "INVFLOW {json}"
  remoteHostname           │  SecCode by audit token (signing)   └─► flows.jsonl (rotated)
                           ▼
                        .allow()            invariant stream --format eslogger --nefilter-log
```

## Layout

| Path | What |
|---|---|
| `macos/InvariantNetFilter/Package.swift` | `InvariantFlowCore`: record encoding, audit-token parsing, config, rotating writer, cache. Pure Foundation; `swift test` runs on macOS and Linux |
| `macos/InvariantNetFilter/Extension/` | the system extension: `FilterDataProvider`, `ProcessIdentity`, `main.swift` |
| `macos/InvariantNetFilter/App/` | SwiftUI host app that activates the extension and enables the filter (also `--activate` / `--deactivate` headless) |
| `macos/InvariantNetFilter/project.yml` | XcodeGen spec: targets, entitlements, Info.plist keys, embedding |
| `deploy/macos/invariant-netfilter.mobileconfig` | MDM template: pre-approves the system extension and the content filter |
| `tests/fixtures/nefilter_flow.json` | record contract checked by both the Swift and Python test suites |
| `src/invariant/collectors/nefilter.py` | Python reader for log-stream and file output |

## Build

Requirements: Xcode 16 or later (macOS 15 SDK; the code uses `remoteFlowEndpoint` there and falls back on older systems), macOS 13+ target, [XcodeGen](https://github.com/yonaskolb/XcodeGen),
and an Apple Developer team with the **Network Extensions** capability (content filter, system extension).

```bash
cd macos/InvariantNetFilter
swift test                                   # core tests
brew install xcodegen && xcodegen generate   # writes InvariantNetFilter.xcodeproj (git-ignored)
open InvariantNetFilter.xcodeproj
```

In Xcode, set your team (or put it in `project.yml` under `DEVELOPMENT_TEAM`). If you change
the bundle ids, change `INVARIANT_APP_ID`, `INVARIANT_EXT_ID` and `INVARIANT_APP_GROUP` in
`project.yml` and the identifiers in the mobileconfig. The extension's bundle name must stay
equal to its bundle id; `project.yml` already does that.

For distribution: archive, sign with Developer ID (the profiles must include the Network
Extension entitlement), notarize, staple. System extensions only activate from an app in
`/Applications`.

## Install and run (one Mac)

```bash
# 1. optional: report only model endpoints instead of every outbound flow
sudo mkdir -p "/Library/Application Support/Invariant"
invariant catalog --format nefilter | sudo tee "/Library/Application Support/Invariant/netfilter.json"
#    (use --nefilter-mode all to keep every flow: needed for generic beacon detection)

# 2. install and activate
cp -R InvariantNetFilter.app /Applications/
open /Applications/InvariantNetFilter.app        # click "Install and enable", approve in System Settings

# 3. stream both macOS sensors into the engine
sudo eslogger exec create rename unlink close \
  | sudo invariant stream --format eslogger --nefilter-log --respond
```

`--nefilter-log` runs `log stream --style ndjson --level info --predicate 'subsystem ==
"com.skbellevue.invariant.netfilter"'` and merges its records with the eslogger events. A
1.5-second re-order buffer (`--reorder-ms`) puts events from the two sources back in timestamp
order, so a model call that reaches the log a moment after the shell it led to is still joined
to it (INV-L3-001).

File alternative to the unified log (survives `log` rate limiting; rotated at 50 MB):

```bash
sudo invariant stream --format eslogger \
  --follow "nefilter:/private/var/root/Library/Group Containers/<TEAMID>.com.skbellevue.invariant/flows.jsonl"
```

The exact path is logged at start-up: `log show --last 1h --predicate 'subsystem ==
"com.skbellevue.invariant.netfilter" AND category == "control"'`.

## Fleet deployment (MDM)

1. Sign and notarize the app; deploy it to `/Applications` with your MDM.
2. Fill in `deploy/macos/invariant-netfilter.mobileconfig`: Team ID, the extension's designated
   requirement (`codesign -d -r- …/com.skbellevue.invariant.netfilter.extension.systemextension`),
   fresh UUIDs, and `VendorConfig/config` (the JSON from `invariant catalog --format nefilter`).
3. Deploy the profile *before* the app is first launched, so users see no approval prompts.
4. Run the app once (`InvariantNetFilter --activate` from a script) to activate the extension.
5. Run the invariant streamer as a LaunchDaemon (see `deploy/macos/`), adding `--nefilter-log`.

## Verify it works

```bash
log show --last 5m --info --predicate 'subsystem == "com.skbellevue.invariant.netfilter"' | head
curl -s https://api.openai.com >/dev/null      # from Terminal: a flow from curl should appear
sudo log stream --style ndjson --level info --predicate 'subsystem == "com.skbellevue.invariant.netfilter"' \
  | invariant stream --format nefilter --min-severity low
```

`curl` is on the high-risk list, so the last command should print an INV-L2-001 alert for
`curl` reaching `openai` (no key needed: the connection itself is the signal).

## Limits and design notes

* **Hostnames.** `remoteHostname` is often nil: macOS fills it only when the app resolved the
  name through system APIs. Records always carry IP and port; match IPs back to names with your
  DNS logs, or run in `all` mode and let the engine's catalog match on what is present. In
  `catalog` mode a flow with no hostname is reported only if its port is listed (e.g. 11434).
* **Missing audit tokens.** Apple's forums report flows from some apps (for example Firefox on
  macOS 15) without `sourceAppAuditToken`. The extension uses `sourceProcessAuditToken`
  (macOS 13+) first and the app token as a fallback; a flow with neither is still recorded
  (destination, protocol) but without pid, path or signature. macOS has no
  `sourceAppIdentifier` (it is iOS-only), so the signing id always comes from the code
  signature. `fields.token_source` says which token was used, and `fields.app_pid` names the
  responsible app when a helper or XPC service opened the connection for it.
* **Volume.** `all` mode on a busy developer Mac produces many records; the unified log may
  rate-limit. Use the JSONL file for completeness, or `catalog` mode.
* **No DNS-only view.** The extension sees connections, not queries. A model reached through a
  proxy appears as a connection to the proxy; attribute it with proxy logs.
* **Inbound flows** are not recorded; they are not part of the L2 invariant.
* **Monitor-only by design.** A blocking mode (deny model endpoints to unsanctioned processes)
  is a small change in `handleNewFlow`, but it turns a sensor into an enforcement point that can
  break work; enforce at the AI gateway first.
