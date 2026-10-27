#!/usr/bin/env bash
# Starts the victim's three services: rsyslog, the SSH server and the Wazuh
# agent. The agent enrols with the manager on first start.
set -euo pipefail

stop() {
  /var/ossec/bin/wazuh-control stop || true
  [[ -f /run/sshd.pid ]] && kill "$(cat /run/sshd.pid)" 2>/dev/null || true
  [[ -f /run/rsyslogd.pid ]] && kill "$(cat /run/rsyslogd.pid)" 2>/dev/null || true
  exit 0
}
trap stop TERM INT

# Host keys are made at start, not at build, so no two labs share them.
ssh-keygen -A >/dev/null
mkdir -p /run/sshd
touch /var/log/auth.log /var/log/syslog

# An empty ld.so.preload is a no-op for the dynamic linker, but its presence
# lets the agent watch it in real time from the start. Anything written to it
# then raises an alert at once (dynamic linker hijacking, ATT&CK T1574.006).
touch /etc/ld.so.preload

rm -f /run/rsyslogd.pid
rsyslogd
/usr/sbin/sshd
/var/ossec/bin/wazuh-control start

# Show the agent's own log as the container log.
tail -F /var/ossec/logs/ossec.log &
wait $!
