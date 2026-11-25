#!/bin/zsh
# Invariant on macOS: stream Endpoint Security events into the detection engine.
# Installed by deploy/macos/README in /Library/Application Support/Invariant/ and run by
# the LaunchDaemon com.invariant.eslogger (as root). eslogger itself needs Full Disk
# Access (grant it to /usr/bin/eslogger with an MDM PPPC profile, SystemPolicyAllFiles).
set -euo pipefail

INVARIANT_HOME="/Library/Application Support/Invariant"
PYTHON="${INVARIANT_HOME}/venv/bin/python"
CONFIG="${INVARIANT_HOME}/invariant.yaml"
LOG_DIR="/var/log/invariant"
mkdir -p "$LOG_DIR"

CONFIG_ARGS=()
[[ -f "$CONFIG" ]] && CONFIG_ARGS=(-c "$CONFIG")

# exec: process lineage, AI-CLI abuse, recon     create/close: script lifecycle, persistence, staging
# rename/unlink: destructive-rate and canary detection
# --net-interval samples TCP connections with psutil for the L2 egress layer (Endpoint Security
# has no network events); remove it if you feed network telemetry from a Network Extension or proxy.
/usr/bin/eslogger exec create rename unlink close \
  | "$PYTHON" -m invariant "${CONFIG_ARGS[@]}" stream --format eslogger --net-interval 5 --respond \
      --min-severity medium >> "$LOG_DIR/alerts.log" 2>> "$LOG_DIR/invariant.err"
