#!/usr/bin/env bash
# End-to-end detection test.
#
# 1. Checks that the victim's agent is connected to the manager.
# 2. Makes 12 failed SSH logins to the victim, as a user name that is new on
#    every run, so old alerts cannot make the test pass.
# 3. Waits for the manager to raise rule 5710 (login as a user that does not
#    exist) and rule 5712 (brute force: 8 or more of those from one address
#    within 120 seconds).
# 4. Waits for the 5712 alert to reach the indexer, where the dashboard reads it.
#
# Exits 0 only if every step passes. Writes the alerts it found to
# tmp/last-test/ for the evidence folder.
set -euo pipefail
cd "$(dirname "$0")/.."

attempts=12
timeout_s=120
user="probe-$(date +%s)"
outdir="tmp/last-test"

pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1" >&2; exit 1; }

# wait_until SECONDS COMMAND...: reruns COMMAND every 3 seconds until it
# succeeds or SECONDS run out.
wait_until() {
  local limit="$1"; shift
  local start=$SECONDS
  until "$@"; do
    (( SECONDS - start >= limit )) && return 1
    sleep 3
  done
}

manager() { docker compose exec -T wazuh.manager "$@"; }

# --- 1. Agent ----------------------------------------------------------------
agent_active() {
  manager /var/ossec/bin/agent_control -l 2>/dev/null | grep -q 'Name: victim,.*Active$'
}
wait_until 60 agent_active || fail "agent 'victim' is not active on the manager (is the lab up? try: make status)"
pass "agent 'victim' is active on the manager"

# Rule 5712 has ignore="60": after it fires, Wazuh does not raise it again
# for 60 seconds. A second run inside that window would fail for the wrong
# reason, so wait it out.
last_5712_age() {
  manager sh -c 'ts=$(grep "\"id\":\"5712\"" /var/ossec/logs/alerts/alerts.json | tail -n 1 \
      | grep -o "\"timestamp\":\"[^\"]*\"" | head -n 1 | cut -d"\"" -f4)
    [ -n "$ts" ] && echo $(( $(date +%s) - $(date -d "$ts" +%s) ))' 2>/dev/null || true
}
age="$(last_5712_age)"
if [[ "$age" =~ ^[0-9]+$ ]] && (( age < 65 )); then
  echo "      rule 5712 fired ${age}s ago and Wazuh mutes it for 60s; waiting $(( 65 - age ))s"
  sleep $(( 65 - age ))
fi

# --- 2. Failed logins --------------------------------------------------------
docker compose --profile test run --rm --no-deps probe victim "$user" "$attempts" >/dev/null
pass "made $attempts failed SSH logins to victim as '$user'"

# --- 3. Alerts on the manager -------------------------------------------------
mkdir -p "$outdir"
alerts_file="$outdir/manager-alerts.json"

fetch_alerts() {
  manager grep -F "\"srcuser\":\"$user\"" /var/ossec/logs/alerts/alerts.json > "$alerts_file" 2>/dev/null || true
}
has_rule() { fetch_alerts; grep -q "\"id\":\"$1\"" "$alerts_file"; }

wait_until "$timeout_s" has_rule 5710 || fail "manager raised no rule 5710 alert for '$user' within ${timeout_s}s"
pass "manager raised rule 5710 (invalid user)"

wait_until "$timeout_s" has_rule 5712 || fail "manager raised no rule 5712 alert for '$user' within ${timeout_s}s"
pass "manager raised rule 5712 (SSH brute force)"

# Wazuh writes alerts as it reads the log, so count only after 5712 is in.
sleep 3
fetch_alerts
echo "      alerts for '$user': $(grep -c '"id":"5710"' "$alerts_file") x 5710, $(grep -c '"id":"5712"' "$alerts_file") x 5712"

# --- 4. Alert in the indexer ----------------------------------------------------
# The query runs inside the manager container, which already holds the CA
# certificate and the indexer password. printf is a shell builtin, so the
# password reaches curl on stdin and never appears in a command line.
query="{\"query\":{\"bool\":{\"filter\":[{\"term\":{\"rule.id\":\"5712\"}},{\"term\":{\"data.srcuser\":\"$user\"}}]}}}"
indexer_file="$outdir/indexer-count.json"

indexed() {
  manager sh -c 'printf "user = \"admin:%s\"\n" "$INDEXER_PASSWORD" | curl -s -K - \
      --cacert /etc/ssl/lab/root-ca.pem -H "Content-Type: application/json" \
      -d "$1" "https://wazuh.indexer:9200/wazuh-alerts-*/_count"' sh "$query" > "$indexer_file" 2>/dev/null || return 1
  grep -Eq '"count":[1-9]' "$indexer_file"
}
wait_until "$timeout_s" indexed || fail "rule 5712 alert for '$user' did not reach the indexer within ${timeout_s}s (last reply: $(cat "$indexer_file"))"
pass "rule 5712 alert is in the indexer (wazuh-alerts-*)"

echo
echo "All checks passed. Alerts saved in $alerts_file"
