#!/usr/bin/env bash
# The week-8 vulnerability-management loop: scan, (triage,) fix, re-scan, prove.
#
#   make vuln
#
# It builds the target image unpatched, scans it (the "before" report), builds
# it again with the three triaged fixes applied, scans that (the "after"
# report), then checks that the fixed findings are gone and the deferred one is
# still there. The raw scans go under tmp/ (git-ignored); the proof is written
# to docs/evidence/vuln/summary.json.
#
# The triage itself — why these three findings and not the others — is in
# docs/vuln-report.md. This script runs the loop and verifies the result.
#
# Cloud VM: run it through cloud/home-soc-lab/vuln.sh (bootcamp repo), which
# sets the registry-mirror and proxy environment. On a normal host, just
# `make vuln`.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
cd "$repo"

before_img="home-soc-lab/vuln:before"
after_img="home-soc-lab/vuln:after"
raw="tmp/vuln"
evdir="docs/evidence/vuln"
dockerfile="${VULN_DOCKERFILE:-vuln/Dockerfile.target}"
mkdir -p "$raw" "$evdir"

echo "==> 1/5  Build the target image (unpatched)"
# shellcheck disable=SC2086
docker build ${VULN_BUILD_EXTRA:-} --build-arg REMEDIATE=0 \
  -t "$before_img" -f "$dockerfile" vuln

echo "==> 2/5  Scan the unpatched target  (before)"
vuln/scan.sh "$before_img" "$raw/before.json"

echo "==> 3/5  Remediate: build the target with the three fixes applied"
# shellcheck disable=SC2086
docker build ${VULN_BUILD_EXTRA:-} --build-arg REMEDIATE=1 \
  -t "$after_img" -f "$dockerfile" vuln

echo "==> 4/5  Re-scan the remediated target  (after)"
vuln/scan.sh "$after_img" "$raw/after.json"

echo "==> 5/5  Prove closure"
python3 vuln/assess.py "$raw/before.json" "$raw/after.json" "$evdir/summary.json"
