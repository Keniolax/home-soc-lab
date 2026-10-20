#!/usr/bin/env bash
# Checks that this machine can run the lab, before anything starts.
# Each failure says what to fix.
set -euo pipefail
cd "$(dirname "$0")/.."

failed=0
ok()   { printf '  ok    %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n        %s\n' "$1" "$2"; failed=1; }

echo "preflight:"

if ! command -v docker >/dev/null 2>&1; then
  bad "docker CLI" "Install Docker Engine, Docker Desktop or Colima."
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  bad "container runtime" "Docker is installed but not running. Start it (for Colima: colima start --memory 4)."
  exit 1
fi
ok "container runtime is running"

# Volume subpaths need Compose 2.30 or later.
compose_version="$(docker compose version --short 2>/dev/null || echo 0)"
compose_major="${compose_version%%.*}"
compose_rest="${compose_version#*.}"
compose_minor="${compose_rest%%.*}"
if (( compose_major > 2 || (compose_major == 2 && compose_minor >= 30) )); then
  ok "docker compose $compose_version"
else
  bad "docker compose $compose_version" "Upgrade to Docker Compose 2.30 or later."
fi

# The four services peak at about 3 GB. Below 3.8 GB the indexer gets killed.
mem_bytes="$(docker info --format '{{.MemTotal}}')"
mem_gb="$(awk -v b="$mem_bytes" 'BEGIN { printf "%.1f", b / 1024 / 1024 / 1024 }')"
if (( mem_bytes >= 3800 * 1024 * 1024 )); then
  ok "runtime memory ${mem_gb} GB"
else
  bad "runtime memory ${mem_gb} GB" "Give the runtime at least 4 GB (Colima: colima stop && colima start --memory 4)."
fi

# OpenSearch refuses to start below this kernel setting.
map_count="$(docker run --rm --network none ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac cat /proc/sys/vm/max_map_count)"
if (( map_count >= 262144 )); then
  ok "vm.max_map_count $map_count"
else
  bad "vm.max_map_count $map_count" "Run on the Docker host: sudo sysctl -w vm.max_map_count=262144"
fi

# Colima and Docker Desktop keep images in a disk file that grows on this
# machine's disk and does not shrink. The first pull needs about 20 GB. When
# a VM's disk file cannot grow, Docker fails with "input/output error".
need_gb=3
for image in $(docker compose config --images 2>/dev/null | grep '@sha256:'); do
  docker image inspect "$image" >/dev/null 2>&1 || need_gb=20
done
free_gb="$(df -Pk . | awk 'NR == 2 { printf "%d", $4 / 1024 / 1024 }')"
if (( free_gb >= need_gb )); then
  ok "disk: ${free_gb} GB free (needs ${need_gb} GB)"
else
  bad "disk: ${free_gb} GB free (needs ${need_gb} GB)" "Free disk space on this machine first."
fi

port="$(grep -E '^DASHBOARD_PORT=' .env 2>/dev/null | cut -d= -f2 || true)"
port="${port:-8443}"
if docker compose ps --status running --services 2>/dev/null | grep -qx 'wazuh.dashboard'; then
  ok "port $port (the lab already holds it)"
elif (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
  bad "port $port" "Something already listens on 127.0.0.1:$port. Set DASHBOARD_PORT in .env."
else
  ok "port $port is free"
fi

if (( failed )); then
  echo "preflight: fix the items marked FAIL, then run make up again."
  exit 1
fi
