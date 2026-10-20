#!/usr/bin/env bash
# Makes failed SSH logins against one host, for the detection test.
#
# Usage: ssh-probe HOST USER [COUNT]
#
# USER should not exist on HOST. The client offers no key and no password,
# so every attempt fails, and sshd logs "Invalid user USER from ...".
set -euo pipefail

host="${1:?usage: ssh-probe HOST USER [COUNT]}"
user="${2:?usage: ssh-probe HOST USER [COUNT]}"
count="${3:-12}"

if ! [[ "$count" =~ ^[0-9]+$ ]] || (( count < 1 || count > 50 )); then
  echo "ssh-probe: COUNT must be a number from 1 to 50" >&2
  exit 2
fi

for _ in $(seq 1 "$count"); do
  ssh -o BatchMode=yes \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 \
      -o LogLevel=ERROR \
      "${user}@${host}" true 2>/dev/null || true
done

echo "ssh-probe: made ${count} failed logins to ${host} as '${user}'"
