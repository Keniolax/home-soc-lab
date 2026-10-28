#!/usr/bin/env python3
"""The threat hunt: from a hypothesis to concrete IOCs, over the sensor logs.

A hunt is not scrolling the logs until something looks odd. It starts from a
hypothesis about how an attacker behaves, turns that into queries, and follows
the answers. This one asks: is a host inside the network beaconing to an
external command-and-control server?

It reads Zeek's metadata from tmp/net-logs/zeek and prints each step
(hypothesis -> query -> finding), then extracts the IOCs and writes them to
docs/evidence/hunt/. It exits non-zero if the hunt finds no C2 that meets the
criteria, so the run can fail: on benign traffic, it finds nothing and says so.
"""
from __future__ import annotations

import json
import pathlib
import sys

import hunt_lib as H

ROOT = pathlib.Path(__file__).resolve().parent.parent
ZEEK = ROOT / "tmp/net-logs/zeek"
EVE = ROOT / "tmp/net-logs/suricata/raw/eve.json"  # this run's Suricata output
EVIDENCE = ROOT / "docs/evidence/hunt"


def banner(step: str, text: str) -> None:
    print(f"\n=== {step} ===\n{text}")


def suricata_alerts() -> dict:
    """Signatures that fired in Suricata's eve.json (the SIEM-side detection)."""
    sigs: dict[str, int] = {}
    if EVE.exists():
        for line in EVE.read_text().splitlines():
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if e.get("event_type") == "alert":
                sig = e["alert"]["signature"]
                sigs[sig] = sigs.get(sig, 0) + 1
    return sigs


def main() -> int:
    conn = H.read_zeek(ZEEK / "conn.log")
    http = H.read_zeek(ZEEK / "http.log")
    dns = H.read_zeek(ZEEK / "dns.log")
    if not conn:
        print(f"hunt: no Zeek logs in {ZEEK}; run the sensor first", file=sys.stderr)
        return 2

    banner("HYPOTHESIS",
           "A host inside the network is infected and beaconing to an external\n"
           "command-and-control server. If so, one internal host will contact one\n"
           "external address far more than any other, probably over HTTP, probably\n"
           "by raw IP with no DNS lookup, and send POST requests back to it.")

    r = H.classify_c2(conn, http, dns)

    banner("QUERY 1  (conn.log)  internal -> external, by connection count",
           "\n".join(
               f"  {b['orig']:<15} -> {b['resp']:<16} {b['conns']:>4} conns"
               f"  {b['orig_bytes']:>8} B sent  mean gap {b['interval_mean_s']}s"
               for b in r["beacons"][:6]) or "  (no external connections)")

    if r["query2"]:
        q2, top = r["query2"], r["top"]
        banner("QUERY 2  (http.log + dns.log)  how was it addressed?",
               f"  HTTP Host header(s) to {top['resp']}: {q2['hosts'] or '(none)'}\n"
               f"  Reached by raw IP literal (no domain): {q2['raw_ip']}\n"
               f"  Ever returned as a DNS answer in the capture: {q2['via_dns']}")
    if r["query3"]:
        q3 = r["query3"]
        banner("QUERY 3  (http.log)  the conversation with it",
               f"  Methods: {q3['methods']}\n"
               f"  Top URIs: {q3['uris'][:4]}\n"
               f"  User-Agents: {[u for u, _ in q3['uas']]}")

    findings = r["findings"]
    banner("FINDING", _describe(findings))

    sigs = suricata_alerts()
    if sigs:
        banner("SIGNATURE DETECTION  (Suricata eve.json -> SIEM)",
               "\n".join(f"  {c:>4}x  {s}" for s, c in sigs.items()))

    if not findings:
        print("\nhunt: no command-and-control traffic found. Nothing to extract.")
        return 1

    iocs = _iocs(findings, sigs)
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / "iocs.json").write_text(json.dumps(iocs, indent=2) + "\n")
    banner("IOCs  (written to docs/evidence/hunt/iocs.json)",
           json.dumps(iocs, indent=2))
    return 0


def _describe(findings: list[dict]) -> str:
    if not findings:
        return "  No internal host beaconed to an external C2 server."
    f = findings[0]
    return (
        f"  {f['infected_host']} is beaconing to {f['c2_server']}:{f['c2_port']} over HTTP.\n"
        f"  {f['http_requests']} requests over {round(f['beacon_span_s']/60)} min,"
        f" mean gap {f['beacon_mean_interval_s']}s.\n"
        f"  Reached by raw IP with no DNS lookup, POSTing to {f['c2_uris']}.\n"
        f"  User-Agent is not a real browser: {f['malware_user_agent']}\n"
        f"  This is MITRE ATT&CK {f['mitre']}, Application Layer Protocol: Web.")


def _iocs(findings: list[dict], suricata: dict) -> dict:
    f = findings[0]
    return {
        "hunt": "C2 beaconing over HTTP",
        "capture": "2024-09-04 traffic-analysis exercise (malware-traffic-analysis.net)",
        "network": {
            "c2_ip": f["c2_server"],
            "c2_port": f["c2_port"],
            "c2_uris": f["c2_uris"],
            "malware_user_agent": f["malware_user_agent"],
        },
        "host": {"infected_host": f["infected_host"]},
        "behaviour": {
            "beacon_span_s": f["beacon_span_s"],
            "beacon_mean_interval_s": f["beacon_mean_interval_s"],
            "http_requests": f["http_requests"],
            "addressed_by_raw_ip": f["addressed_by_raw_ip"],
            "mitre": f["mitre"],
        },
        "siem_signatures": suricata,
    }


if __name__ == "__main__":
    sys.exit(main())
