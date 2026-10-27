#!/usr/bin/env bash
# Measure what the lab's SIEM detects. Emulates real ATT&CK techniques on the
# victim, then scores each as detected, logged, or blind and writes the
# coverage heatmap and matrix.
#
# Run `make up` first. The lab must be healthy and the agent connected.
set -euo pipefail
cd "$(dirname "$0")/.."

compose() { docker compose "$@"; }
manager() { compose exec -T wazuh.manager "$@"; }

wait_until() {  # wait_until SECONDS CMD...
  local limit="$1"; shift; local start=$SECONDS
  until "$@"; do (( SECONDS - start >= limit )) && return 1; sleep 3; done
}
agent_active() { manager /var/ossec/bin/agent_control -l 2>/dev/null | grep -q 'Name: victim,.*Active$'; }
analysisd_up() { manager sh -c "/var/ossec/bin/wazuh-control status 2>/dev/null | grep -q 'wazuh-analysisd is running'"; }

echo "coverage: checking the lab is up"
wait_until 60 agent_active || { echo "coverage: agent 'victim' is not active. Run: make up" >&2; exit 1; }

echo "coverage: fetching the pinned atomics"
bash coverage/fetch-atomics.sh

echo "coverage: recording the agent's FIM scope"
mkdir -p tmp/coverage
dirs_csv="$(compose exec -T victim sh -c "awk -F'[<>]' '/<directories>/{print \$3}' /var/ossec/etc/ossec.conf | paste -sd,")"
python3 - "$dirs_csv" > tmp/coverage/syscheck.json <<'PY'
import json, sys
dirs = [d for part in sys.argv[1].split(",") for d in part.split(",") if d.strip()]
print(json.dumps({"dirs": dirs}))
PY

# A coverage assessment turns on full event archiving so we can see every event
# the SIEM receives, not only the ones that alerted. Restored at the end.
archive_was_on="$(manager sh -c "grep -q '<logall_json>yes' /var/ossec/etc/ossec.conf && echo yes || echo no")"
restore_archiving() {
  [ "${COVERAGE_NO_ARCHIVE:-0}" = 1 ] && return 0
  [ "$archive_was_on" = yes ] && return 0
  manager sed -i 's#<logall_json>yes</logall_json>#<logall_json>no</logall_json>#' /var/ossec/etc/ossec.conf 2>/dev/null || true
  compose restart wazuh.manager >/dev/null 2>&1 &
}
trap restore_archiving EXIT

if [ "${COVERAGE_NO_ARCHIVE:-0}" != 1 ] && [ "$archive_was_on" = no ]; then
  echo "coverage: enabling event archiving for the assessment"
  manager sed -i 's#<logall_json>no</logall_json>#<logall_json>yes</logall_json>#' /var/ossec/etc/ossec.conf
  compose restart wazuh.manager >/dev/null 2>&1
  wait_until 120 analysisd_up || { echo "coverage: manager did not come back" >&2; exit 1; }
  wait_until 90 agent_active  || { echo "coverage: agent did not reconnect" >&2; exit 1; }
fi

echo "coverage: emulating techniques on the victim"
python3 coverage/emulate.py

echo "coverage: letting the last alerts settle"
sleep 20

echo "coverage: collecting what the SIEM saw"
python3 coverage/collect.py

echo "coverage: scoring"
python3 coverage/score.py

if python3 -c 'import matplotlib' 2>/dev/null; then
  echo "coverage: rendering the heatmap"
  python3 coverage/render_heatmap.py
else
  echo "coverage: matplotlib not installed; skipping the PNG (layer JSON is the source of truth)" >&2
fi

echo "coverage: done. See coverage/navigator/coverage-layer.json and docs/evidence/coverage/matrix.md"
