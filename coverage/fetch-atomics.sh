#!/usr/bin/env bash
# Fetch the Atomic Red Team atomics this assessment runs, pinned to the commit
# in techniques.yaml, into tmp/ (git-ignored). Idempotent.
set -euo pipefail
cd "$(dirname "$0")/.."

commit="$(awk '/^  commit:/ { print $2; exit }' coverage/techniques.yaml)"
dest="tmp/coverage/atomic-red-team"
repo="https://github.com/redcanaryco/atomic-red-team.git"

# The technique folders we need, read straight from techniques.yaml.
mapfile -t ids < <(awk '/^  - id:/ { print $3 }' coverage/techniques.yaml | sort -u)

if [ -d "$dest/.git" ] && [ "$(git -C "$dest" rev-parse HEAD 2>/dev/null)" = "$commit" ]; then
  echo "fetch-atomics: already at $commit"
  exit 0
fi

rm -rf "$dest"
mkdir -p "$dest"
git -C "$dest" init -q
git -C "$dest" remote add origin "$repo"
git -C "$dest" config core.sparseCheckout true
git -C "$dest" sparse-checkout init --cone >/dev/null 2>&1 || true
printf 'atomics/%s\n' "${ids[@]}" > "$dest/.git/info/sparse-checkout"
git -C "$dest" fetch -q --depth 1 origin "$commit"
git -C "$dest" checkout -q "$commit"
echo "fetch-atomics: checked out $commit (${#ids[@]} techniques)"
