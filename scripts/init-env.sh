#!/usr/bin/env bash
# Creates .env from .env.example and fills each empty password with a random
# one. Leaves an existing .env alone.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -f .env ]]; then
  echo "init-env: .env exists, keeping it"
  exit 0
fi

# 24 random letters and digits, plus "." because the Wazuh API demands a
# symbol. Retries until the password has upper case, lower case and a digit.
new_password() {
  local p
  while :; do
    p="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24 || true)"
    [[ "$p" =~ [A-Z] && "$p" =~ [a-z] && "$p" =~ [0-9] ]] && break
  done
  printf '%s.' "$p"
}

umask 077
tmp="$(mktemp .env.XXXXXX)"
trap 'rm -f "$tmp"' EXIT

while IFS= read -r line || [[ -n "$line" ]]; do
  if [[ "$line" =~ ^([A-Z_]+_PASSWORD)=$ ]]; then
    printf '%s=%s\n' "${BASH_REMATCH[1]}" "$(new_password)" >> "$tmp"
  else
    printf '%s\n' "$line" >> "$tmp"
  fi
done < .env.example

mv "$tmp" .env
trap - EXIT
echo "init-env: created .env with random passwords (mode 600)"
