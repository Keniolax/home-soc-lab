#!/usr/bin/env bash
# Fetch the one malicious capture this hunt runs on, pinned so the result
# repeats. The capture is a 2024-09-04 traffic-analysis exercise from
# malware-traffic-analysis.net: a Windows host in an Active Directory domain
# beaconing to an HTTP command-and-control server.
#
# The capture is evidence, not a program. Nothing in it is ever run. The zip
# holds one .pcap and no sample. It is not committed to the repo: it is
# downloaded here into pcaps/, which git ignores, and checked by hash.
#
# Source page: https://www.malware-traffic-analysis.net/2024/09/04/index.html
# The zip password scheme (infected_YYYYMMDD) is on the site's About page.
set -euo pipefail
cd "$(dirname "$0")/.."

URL="https://www.malware-traffic-analysis.net/2024/09/04/2024-09-04-traffic-analysis-exercise.pcap.zip"
ZIP_SHA256="84edaf0d73c666a9213b5aa6d1c9a68356c5495728da72ac25521cfe6346dfe6"
PCAP_SHA256="8fee06d0b1686faab4364f5b7a741e736ad7e713d5ca9299ff9161a4b4d4862e"
ZIP_PASSWORD="infected_20240904"

dir="pcaps"
zip="$dir/capture.pcap.zip"
pcap="$dir/capture.pcap"
mkdir -p "$dir"

if [ -f "$pcap" ] && echo "$PCAP_SHA256  $pcap" | sha256sum -c - >/dev/null 2>&1; then
  echo "fetch-pcap: capture.pcap already present and verified"
  exit 0
fi

echo "fetch-pcap: downloading pinned capture"
curl -fsSL --max-time 180 "$URL" -o "$zip"
echo "$ZIP_SHA256  $zip" | sha256sum -c - \
  || { echo "fetch-pcap: zip hash mismatch; refusing to use it" >&2; exit 1; }

# -o overwrite, -P password, -j junk paths, -d into dir. The archive holds one
# file; rename it to a stable name.
unzip -o -j -P "$ZIP_PASSWORD" "$zip" -d "$dir" >/dev/null
extracted="$(unzip -Z1 "$zip" | head -n1)"
mv -f "$dir/$(basename "$extracted")" "$pcap"
rm -f "$zip"

echo "$PCAP_SHA256  $pcap" | sha256sum -c - \
  || { echo "fetch-pcap: pcap hash mismatch; refusing to use it" >&2; exit 1; }
echo "fetch-pcap: $pcap ready ($(wc -c < "$pcap") bytes, hash verified)"
