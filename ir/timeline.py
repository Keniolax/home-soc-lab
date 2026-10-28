#!/usr/bin/env python3
"""Reconstruct the incident timeline from the network evidence.

Reads the Zeek metadata and Suricata alerts the sensor wrote (tmp/net-logs),
finds the infected host and its C2 server with the week-6 hunt logic, and prints
a chronological timeline where every line cites the log it came from, so each
claim can be checked against the evidence. Deterministic: same capture, same
timeline. Writes docs/evidence/ir/timeline.json.

This is the ground truth the AI-drafted timeline in docs/ir-report.md is checked
against.
"""
from __future__ import annotations

import datetime as dt
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "network"))
import hunt_lib as H  # noqa: E402

ZEEK = ROOT / "tmp/net-logs/zeek"
EVE = ROOT / "tmp/net-logs/suricata/raw/eve.json"
EVIDENCE = ROOT / "docs/evidence/ir"


def utc(epoch: float) -> str:
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC")


def alert_times(path: pathlib.Path) -> list[float]:
    """Packet times of Suricata alert events, from eve.json."""
    times = []
    if not path.exists():
        return times
    for line in path.read_text().splitlines():
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if e.get("event_type") == "alert" and e.get("timestamp"):
            ts = e["timestamp"].replace("Z", "+00:00")
            try:
                times.append(dt.datetime.fromisoformat(ts).timestamp())
            except ValueError:
                pass
    return times


def build_timeline(conn: list[dict], http: list[dict], dns: list[dict],
                   alert_ts: list[float]) -> dict:
    """Return the incident facts and a chronological list of events.

    Each event is {epoch, utc, event, source}. The facts are the numbers the
    report cites; the events are what an analyst would put on a timeline.
    """
    finding = (H.classify_c2(conn, http, dns)["findings"] or [None])[0]
    if finding is None:
        return {"finding": None, "events": [], "facts": {}}

    c2 = finding["c2_server"]
    host = finding["infected_host"]
    conn_ts = sorted(float(r["ts"]) for r in conn if r.get("ts"))
    c2_conn_ts = sorted(float(r["ts"]) for r in conn
                        if r.get("id.resp_h") == c2 and r.get("ts"))
    c2_http = sorted((float(r["ts"]), r) for r in http
                     if r.get("id.resp_h") == c2 and r.get("ts"))

    events = []

    def add(epoch, event, source):
        events.append({"epoch": epoch, "utc": utc(epoch),
                       "event": event, "source": source})

    add(conn_ts[0],
        f"Capture begins. Baseline traffic from {host} (no C2 yet).",
        "conn.log (earliest record)")
    add(c2_conn_ts[0],
        f"First C2 contact: {host} connects to {c2}. The host is already "
        f"beaconing, so the initial infection is earlier than this capture.",
        "conn.log (first flow to the C2)")

    # Registration vs. check-in: the first non-/foots.php request looks like a
    # registration; /foots.php is the repeating check-in.
    reg = next((r for t, r in c2_http if r.get("uri", "").startswith("/index")),
               None)
    if reg:
        add(float(reg["ts"]),
            f"C2 registration request: {reg.get('method')} {reg.get('uri')}.",
            "http.log (first /index request to the C2)")
    first_post = next((r for t, r in c2_http if r.get("method") == "POST"), None)
    if first_post:
        add(float(first_post["ts"]),
            f"First check-in: POST {first_post.get('uri')} to the C2.",
            "http.log (first POST to the C2)")

    if alert_ts:
        add(min(alert_ts),
            "First network detection: a Suricata rule fires on the C2 traffic.",
            "Suricata eve.json (earliest alert)")
    add(c2_conn_ts[-1],
        f"Last C2 activity in the capture: {host} still beaconing to {c2}.",
        "conn.log (last flow to the C2)")
    add(conn_ts[-1], "Capture ends.", "conn.log (latest record)")

    events.sort(key=lambda e: e["epoch"])

    intervals = [b - a for a, b in zip(c2_conn_ts, c2_conn_ts[1:])]
    facts = {
        "infected_host": host,
        "c2_server": c2,
        "c2_port": finding["c2_port"],
        "capture_start_utc": utc(conn_ts[0]),
        "capture_end_utc": utc(conn_ts[-1]),
        "first_c2_contact_utc": utc(c2_conn_ts[0]),
        "last_c2_activity_utc": utc(c2_conn_ts[-1]),
        "c2_connections": len(c2_conn_ts),
        "beacon_span_min": round((c2_conn_ts[-1] - c2_conn_ts[0]) / 60, 1),
        "beacon_mean_interval_s": round(sum(intervals) / len(intervals), 1)
            if intervals else 0,
        "c2_http_requests": len(c2_http),
        "c2_uris": finding["c2_uris"],
        "malware_user_agent": finding["malware_user_agent"],
        "suricata_alerts": len(alert_ts),
        "mitre": [finding["mitre"]],
    }
    return {"finding": finding, "events": events, "facts": facts}


def main() -> int:
    conn = H.read_zeek(ZEEK / "conn.log")
    http = H.read_zeek(ZEEK / "http.log")
    dns = H.read_zeek(ZEEK / "dns.log")
    if not conn:
        print(f"timeline: no Zeek logs in {ZEEK}; run the sensor first",
              file=sys.stderr)
        return 2

    result = build_timeline(conn, http, dns, alert_times(EVE))
    if result["finding"] is None:
        print("timeline: no incident found in the evidence.")
        return 1

    print("=== INCIDENT TIMELINE (all times UTC, from the capture) ===\n")
    for e in result["events"]:
        print(f"  {e['utc']}  {e['event']}")
        print(f"  {'':22}  └─ source: {e['source']}\n")

    f = result["facts"]
    print("=== FACTS (ground truth for verification) ===")
    for k, v in f.items():
        print(f"  {k}: {v}")

    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / "timeline.json").write_text(
        json.dumps({"events": result["events"], "facts": f}, indent=2) + "\n")
    print(f"\ntimeline: wrote {EVIDENCE / 'timeline.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
