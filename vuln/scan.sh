#!/usr/bin/env bash
# Scan one local image with Trivy and write the JSON report to a file.
#
#   vuln/scan.sh <image-ref> <output.json>
#
# On a normal Docker host the defaults are enough: Trivy's own image and its
# public database. The cloud VM overrides a few environment variables so Trivy
# reaches a registry mirror and the agent proxy (see cloud/home-soc-lab/vuln.sh
# in the bootcamp repo):
#   TRIVY_IMAGE          the Trivy scanner image to run
#   TRIVY_DB_REPOSITORY  where Trivy fetches its vulnerability database
#   TRIVY_DOCKER_ARGS    extra `docker run` flags (network, proxy env)
set -euo pipefail

ref="${1:?usage: scan.sh <image-ref> <output.json>}"
out="${2:?usage: scan.sh <image-ref> <output.json>}"
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"

img="${TRIVY_IMAGE:-aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c}"
mkdir -p "$repo/tmp/trivy-cache" "$(dirname "$out")"

# shellcheck disable=SC2086  # TRIVY_DOCKER_ARGS is a deliberate word list.
docker run --rm ${TRIVY_DOCKER_ARGS:-} \
  ${TRIVY_DB_REPOSITORY:+-e TRIVY_DB_REPOSITORY="$TRIVY_DB_REPOSITORY"} \
  -v "$repo/tmp/trivy-cache:/root/.cache/" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  "$img" image --quiet --scanners vuln --pkg-types os \
  --format json "$ref" > "$out"

echo "scan.sh: wrote $out"
