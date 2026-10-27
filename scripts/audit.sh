#!/usr/bin/env bash
# Audits the victim with two tools and saves the results:
#   Lynis 3.0.9             a general hardening scan, scored 0-100
#   Wazuh SCA, CIS policy   the CIS Ubuntu 24.04 Benchmark v1.0.0 checks
#
# Usage: scripts/audit.sh LABEL     (for example: before, after)
# Results go to docs/evidence/hardening/LABEL/.
set -euo pipefail
cd "$(dirname "$0")/.."

label="${1:?usage: scripts/audit.sh LABEL}"
[[ "$label" =~ ^[a-z0-9-]+$ ]] || { echo "audit: LABEL must be lowercase letters, digits or -" >&2; exit 2; }
out="docs/evidence/hardening/$label"
mkdir -p "$out"

# Run a call against the Wazuh API from inside the manager. The API password is
# already in the manager's environment and goes to curl on stdin, never on a
# command line. -k: the API uses a certificate that Wazuh generates for itself.
api() {
  docker compose exec -T wazuh.manager sh -c '
    tok=$(printf "user = \"%s:%s\"\n" "$API_USERNAME" "$API_PASSWORD" \
      | curl -s -k -K - -X POST "https://localhost:55000/security/user/authenticate?raw=true")
    printf "header = \"Authorization: Bearer %s\"\n" "$tok" | curl -s -k -K - "https://localhost:55000$1"
  ' sh "$1"
}

# Pull one value out of JSON with the manager's own Python, so nothing extra
# is needed on this machine.
json() {
  docker compose exec -T wazuh.manager /var/ossec/framework/python/bin/python3 -c "
import json, sys
d = json.load(sys.stdin)
print($1)"
}

# --- Lynis ---------------------------------------------------------------------
echo "audit: running Lynis in the victim"
docker compose exec -T victim lynis audit system --quick --no-colors --quiet >/dev/null 2>&1 || true
report="$(docker compose exec -T victim cat /var/log/lynis-report.dat)"
lynis_index="$(grep -m1 '^hardening_index=' <<<"$report" | cut -d= -f2)"
grep '^warning\[\]=' <<<"$report" | cut -d= -f2- | cut -d'|' -f1-2 > "$out/lynis-warnings.txt" || true
grep '^suggestion\[\]=' <<<"$report" | cut -d= -f2- | cut -d'|' -f1-2 > "$out/lynis-suggestions.txt" || true

# --- Wazuh SCA (CIS) --------------------------------------------------------------
# The agent scans when it starts. Restart it so the result reflects the victim now.
agent="$(api '/agents?name=victim&select=id' | json "d['data']['affected_items'][0]['id']")"
started="$(date -u +%s)"
echo "audit: restarting the agent (id $agent) so it runs the CIS scan now"
docker compose exec -T victim /var/ossec/bin/wazuh-control restart >/dev/null
# Wait until the manager holds a CIS scan that finished after the restart.
fresh=no
for _ in $(seq 1 60); do
  fresh="$(api "/sca/$agent?pretty=false" | json "
'yes' if any(x['policy_id'] == 'cis_ubuntu24-04'
             and __import__('datetime').datetime.fromisoformat(x['end_scan']).timestamp() >= $started
             for x in d['data']['affected_items']) else 'no'" || echo no)"
  [[ "$fresh" == yes ]] && break
  sleep 5
done
[[ "$fresh" == yes ]] || { echo "audit: no new CIS scan from the agent within 5 minutes" >&2; exit 1; }

sca="$(api "/sca/$agent?pretty=false")"
read -r pass fail na score < <(json "next(f\"{x['pass']} {x['fail']} {x['invalid']} {x['score']}\" for x in d['data']['affected_items'] if x['policy_id']=='cis_ubuntu24-04')" <<<"$sca")
api "/sca/$agent/checks/cis_ubuntu24-04?result=failed&limit=500&select=id,title&pretty=false" \
  | json "'\n'.join(f\"{c['id']} {c['title']}\" for c in sorted(d['data']['affected_items'], key=lambda c: c['id']))" \
  > "$out/cis-failed.txt"

{
  echo "Victim audit: $label, $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "Lynis 3.0.9 hardening index: $lynis_index / 100 ($(wc -l < "$out/lynis-warnings.txt" | tr -d ' ') warnings, $(wc -l < "$out/lynis-suggestions.txt" | tr -d ' ') suggestions)"
  echo "CIS Ubuntu 24.04 v1.0.0 (Wazuh SCA): score $score% ($pass pass, $fail fail, $na not applicable)"
} | tee "$out/summary.txt"
