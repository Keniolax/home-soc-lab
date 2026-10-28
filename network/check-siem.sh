#!/usr/bin/env bash
# Confirm the network sensor's alerts reached the SIEM.
#
# `make hunt` writes Suricata's eve.json, which the victim's agent ships to the
# manager. The manager's built-in Suricata ruleset raises rule 86601, "Suricata:
# Alert", for each one. This polls the manager's alerts.json until those alerts
# appear, so the sensor-to-SIEM path is proven, not assumed. The agent reads a
# newly created file from the start, so this can take up to a minute.
set -euo pipefail
cd "$(dirname "$0")/.."

timeout_s="${1:-150}"
outdir="tmp/last-test"
mkdir -p "$outdir"
alerts_file="$outdir/suricata-siem-alerts.json"

manager() { docker compose exec -T wazuh.manager "$@"; }

# The signatures this hunt's rules produce. At least the C2-host and the
# User-Agent signature must reach the manager.
want_sig="HOMELAB C2 known-bad host"

fetch() {
  manager grep -F '"id":"86601"' /var/ossec/logs/alerts/alerts.json \
    > "$alerts_file" 2>/dev/null || true
}
have() { fetch; grep -qF "$want_sig" "$alerts_file"; }

echo "check-siem: waiting up to ${timeout_s}s for Suricata alerts on the manager"
start=$SECONDS
until have; do
  if (( SECONDS - start >= timeout_s )); then
    echo "check-siem: FAIL - no Suricata (rule 86601) alert reached the manager in ${timeout_s}s" >&2
    echo "           Is the victim agent up with /var/log/suricata/eve.json mounted?" >&2
    exit 1
  fi
  sleep 5
done

count=$(grep -c '"id":"86601"' "$alerts_file" 2>/dev/null || echo 0)
echo "check-siem: PASS - $count Suricata alert(s) (rule 86601) on the manager"
echo "           distinct signatures:"
grep -o '"signature":"[^"]*"' "$alerts_file" | sort | uniq -c | sed 's/^/             /'
echo "           saved to $alerts_file"
