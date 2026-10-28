#!/usr/bin/env bash
# Run the network sensors over the capture, offline.
#
# Suricata and Zeek both read the .pcap from disk (-r). Nothing is replayed onto
# a live interface and no sample is run; the packets are parsed, the way an
# analyst opens a capture. Each tool is pinned by image digest.
#
#   Suricata -> alerts.    Signature engine. Writes eve.json; the lab's Suricata
#               rules fire on the C2 traffic. The alerts are appended to
#               tmp/net-logs/suricata/eve.json, which the victim's Wazuh agent
#               tails, so they reach the manager (the SIEM).
#   Zeek     -> metadata.  Writes conn.log, http.log, dns.log, ssl.log and more
#               -- one row per connection and per protocol event. The threat
#               hunt queries these.
#
# Output goes to tmp/net-logs/ (git-ignored). Suricata's raw run goes to
# suricata/raw/; its alerts are then appended to suricata/eve.json. The agent
# watches that file, which `make up` creates before the agent starts, and ships
# each line it grows by -- so the file is never deleted here, only appended to,
# which keeps the inode the agent opened and makes the new alerts visible to it.
#
# Usage: run-sensor.sh [RULES_FILE]
#   RULES_FILE defaults to network/suricata/local.rules, and is a path inside
#   the repo. The negative test passes an empty rule file to show the alerts
#   come from the rules:  : > tmp/empty.rules && run-sensor.sh tmp/empty.rules
set -euo pipefail
cd "$(dirname "$0")/.."

SURICATA="jasonish/suricata:7.0.8@sha256:89b300fb5d00f182359a1305543e828a804ede7f1685e75b05f607f7372428c6"
ZEEK="zeek/zeek:6.0.9@sha256:aadcabbe08c7a7fbfdf445d036660426c4ab447f05db699aa8b26fbee66aaf0e"

pcap="pcaps/capture.pcap"
rules="${1:-network/suricata/local.rules}"
suri_out="tmp/net-logs/suricata"
raw="$suri_out/raw"
watched="$suri_out/eve.json"
zeek_out="tmp/net-logs/zeek"

[ -f "$pcap" ] || { echo "run-sensor: $pcap not found; run network/fetch-pcap.sh first" >&2; exit 1; }
[ -f "$rules" ] || { echo "run-sensor: rules file $rules not found" >&2; exit 1; }

# Fresh working dirs for Suricata's raw output and Zeek's logs. The watched file
# is only touched (so it exists) and appended to, never removed.
mkdir -p "$raw" "$zeek_out"
rm -f "$raw"/* "$zeek_out"/*
touch "$watched"

echo "run-sensor: Suricata over $pcap with $rules"
docker run --rm \
  -v "$PWD/$pcap:/capture.pcap:ro" \
  -v "$PWD/$rules:/local.rules:ro" \
  -v "$PWD/$raw:/out" \
  "$SURICATA" -r /capture.pcap -S /local.rules -l /out >/dev/null 2>&1
alerts="$(grep -c '"event_type":"alert"' "$raw/eve.json" 2>/dev/null || true)"
echo "run-sensor: Suricata wrote $(wc -l < "$raw/eve.json") events, $alerts alerts"

# Append this run's events to the file the agent tails. The agent ships the new
# lines to the manager, where the Suricata ruleset raises rule 86601 per alert.
cat "$raw/eve.json" >> "$watched"

echo "run-sensor: Zeek over $pcap"
docker run --rm \
  -v "$PWD/$pcap:/capture.pcap:ro" \
  -v "$PWD/$zeek_out:/out" -w /out \
  "$ZEEK" zeek -r /capture.pcap >/dev/null 2>&1
echo "run-sensor: Zeek wrote $(ls "$zeek_out"/*.log 2>/dev/null | wc -l) logs"
