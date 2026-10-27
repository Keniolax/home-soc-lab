#!/usr/bin/with-contenv bash
# Adjusts the manager's ossec.conf for this lab before Wazuh starts.
#
# compose.yaml mounts this file as /etc/cont-init.d/1-0-lab-config. The image
# runs those scripts in name order, so this one runs after 0-wazuh-init and
# before 2-manager. The order matters: on first start, 2-manager starts Wazuh
# for a short time to set the API password, and any setting changed after
# that comes too late. The mount is read-only, so s6 logs "unable to chown"
# and "unable to change mode" for it. Those lines are harmless.
set -euo pipefail

conf=/var/ossec/etc/ossec.conf

# 1. Vulnerability detection off.
# On first start the scanner unpacks a vulnerability database that ships in
# the image into /var/ossec/queue/vd. It reached 8.3 GB in 72 seconds. On a
# laptop that fills the disk, and this lab's test does not use it.
sed -i '/<vulnerability-detection>/,/<\/vulnerability-detection>/ s|<enabled>yes</enabled>|<enabled>no</enabled>|' "$conf"

# 2. Indexer connector pointed at the lab's indexer.
# The image's ossec.conf sends inventory data to https://0.0.0.0:9200, with
# certificates in /etc/filebeat/certs. Neither exists in this lab. The
# image's own start-up scripts already store the indexer user name and
# password in the Wazuh keystore.
sed -i \
  -e 's|<host>https://0\.0\.0\.0:9200</host>|<host>https://wazuh.indexer:9200</host>|' \
  -e 's|/etc/filebeat/certs/root-ca\.pem|/etc/ssl/lab/root-ca.pem|' \
  -e 's|/etc/filebeat/certs/filebeat\.pem|/etc/ssl/lab/filebeat.pem|' \
  -e 's|/etc/filebeat/certs/filebeat-key\.pem|/etc/ssl/lab/filebeat-key.pem|' \
  "$conf"

# 3. Let a rebuilt agent take over its old name.
# By default the manager refuses a new agent named like an existing one until
# the old one has been disconnected for an hour, so a recreated victim fails
# with "Duplicate agent name". In this lab the old victim is always gone.
if ! grep -q '<force>' "$conf"; then
  sed -i 's|<purge>yes</purge>|<purge>yes</purge>\
    <force>\
      <enabled>yes</enabled>\
      <key_mismatch>yes</key_mismatch>\
      <disconnected_time enabled="yes">0</disconnected_time>\
      <after_registration_time>0</after_registration_time>\
    </force>|' "$conf"
fi

if sed -n '/<vulnerability-detection>/,/<\/vulnerability-detection>/p' "$conf" | grep -q '<enabled>yes</enabled>'; then
  echo "manager-config: vulnerability detection is still on in $conf" >&2
  exit 1
fi
grep -q '<host>https://wazuh.indexer:9200</host>' "$conf" \
  || { echo "manager-config: indexer host not set in $conf" >&2; exit 1; }
grep -q "<after_registration_time>0</after_registration_time>" "$conf" \
  || { echo "manager-config: agent replacement not set in $conf" >&2; exit 1; }
echo "manager-config: vulnerability detection off, indexer connector set, agents may re-enroll"
