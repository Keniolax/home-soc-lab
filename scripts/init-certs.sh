#!/usr/bin/env bash
# Creates the lab's TLS certificates inside the lab-init volume.
#
# Runs once, as root, in the manager image (it has OpenSSL). One private CA
# signs a certificate for each service. The CA key is deleted afterwards, so
# nothing can sign further certificates for this lab. `make down` removes the
# volume, and the next `make up` creates a fresh set.
set -euo pipefail

out=/out
if [[ -f "$out/.certs-done" ]]; then
  echo "init-certs: certificates already exist, nothing to do"
  exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

# Every subject shares this prefix. The indexer config names two of the full
# subjects (admin and wazuh.indexer), so change both places together.
subject="/C=US/O=home-soc-lab/OU=lab"
days=825

openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days "$days" \
  -subj "$subject/CN=home-soc-lab-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out root-ca.pem

# issue NAME CN [SAN]: writes NAME.pem and NAME-key.pem, signed by the CA.
issue() {
  local name="$1" cn="$2" san="${3:-}"
  openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$name-key.pem"
  openssl req -new -key "$name-key.pem" -subj "$subject/CN=$cn" -out "$name.csr"
  {
    echo "basicConstraints=CA:FALSE"
    echo "keyUsage=critical,digitalSignature,keyEncipherment"
    # The indexer uses one certificate for both sides of its TLS links.
    echo "extendedKeyUsage=serverAuth,clientAuth"
    [[ -n "$san" ]] && echo "subjectAltName=$san"
  } > "$name.ext"
  openssl x509 -req -in "$name.csr" -CA root-ca.pem -CAkey ca.key \
    -set_serial "0x$(openssl rand -hex 16)" -days "$days" -sha256 \
    -extfile "$name.ext" -out "$name.pem" 2>/dev/null
}

issue indexer   wazuh.indexer   "DNS:wazuh.indexer,DNS:localhost"
issue dashboard wazuh.dashboard "DNS:wazuh.dashboard,DNS:localhost"
issue filebeat  wazuh.manager   "DNS:wazuh.manager"
issue admin     admin

# place DIR OWNER FILE...: copies files into one directory per service, so
# each container mounts only the keys it needs.
place() {
  local dir="$out/$1" owner="$2"
  shift 2
  mkdir -p "$dir"
  cp root-ca.pem "$@" "$dir/"
  chown -R "$owner" "$dir"
  chmod 0500 "$dir"
  chmod 0444 "$dir"/*.pem
  chmod 0400 "$dir"/*-key.pem
}

# The indexer and dashboard run as UID 1000. In the manager, Filebeat runs as
# root and the Wazuh daemons as user wazuh (UID 999), so 999 owns those files.
place indexer   1000:1000 indexer.pem indexer-key.pem admin.pem admin-key.pem
place dashboard 1000:1000 dashboard.pem dashboard-key.pem
place manager   999:999   filebeat.pem filebeat-key.pem

touch "$out/.certs-done"
echo "init-certs: created certificates for indexer, dashboard and manager"
