#!/usr/bin/env bash
# Writes the indexer's user list, with the passwords from .env, into the
# lab-init volume.
#
# Runs once, as root, in the indexer image. The indexer reads this list only
# when it first creates its security index. To change a password later, run
# `make down`, edit .env, then `make up`.
#
# Only two users exist: admin (people, and Filebeat) and kibanaserver (the
# dashboard's own login). The image's demo users are left out on purpose.
set -euo pipefail

out=/out/security
if [[ -f "$out/.users-done" ]]; then
  echo "init-users: user list already exists, nothing to do"
  exit 0
fi

export JAVA_HOME=/usr/share/wazuh-indexer/jdk
tools=/usr/share/wazuh-indexer/plugins/opensearch-security/tools

# hash.sh reads the password from the named variable, so it never appears in
# a command line. Its stderr is dropped: with no network, Java logs a long
# host-name error that does not affect the hash.
hash_of() {
  local h
  h="$(bash "$tools/hash.sh" -env "$1" 2>/dev/null | tail -n 1)"
  if [[ ! "$h" =~ ^\$2[aby]\$12\$ ]]; then
    echo "init-users: hash.sh did not return a bcrypt hash for $1" >&2
    exit 1
  fi
  printf '%s' "$h"
}

admin_hash="$(hash_of INDEXER_ADMIN_PASSWORD)"
dashboard_hash="$(hash_of DASHBOARD_SERVER_PASSWORD)"

# Start from the image's own security settings, then replace the user list.
mkdir -p "$out"
cp -a /usr/share/wazuh-indexer/config/opensearch-security/. "$out/"

cat > "$out/internal_users.yml" <<EOF
---
_meta:
  type: "internalusers"
  config_version: 2

admin:
  hash: "$admin_hash"
  reserved: true
  backend_roles:
    - "admin"
  description: "Lab administrator"

kibanaserver:
  hash: "$dashboard_hash"
  reserved: true
  description: "Dashboard service account"
EOF

chown -R 1000:1000 "$out"
chmod 0750 "$out"
chmod 0640 "$out"/*.yml

touch "$out/.users-done"
echo "init-users: wrote user list with 2 users"
