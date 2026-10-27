#!/usr/bin/env python3
"""Collect what the SIEM did during each technique's run window.

Pulls the manager's alerts.json and archives.json, and for each technique in
windows.json records the alerts attributable to it (by MITRE technique id, in
the run window) and how many events the SIEM received at all. Writes
tmp/coverage/results.json for the scorer.
"""
from __future__ import annotations

import datetime as dt
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "tmp/coverage"
GRACE_END = 25      # seconds after a technique to still credit a lagging alert
AGENT = "victim"

# T1110 password guessing fires these sshd rules; 5712 also carries MITRE
# T1110, but 5710 does not, so name them to capture both as evidence.
EXTRA_RULE_IDS = {"T1110.001": {"5710", "5712"}}

_TS = re.compile(r"([+-]\d{2})(\d{2})$")


def parse_ts(s: str) -> float:
    s = _TS.sub(r"\1:\2", s)
    return dt.datetime.fromisoformat(s).timestamp()


def pull(remote_path: str, local: pathlib.Path) -> None:
    out = subprocess.run(
        ["docker", "compose", "exec", "-T", "wazuh.manager", "cat", remote_path],
        cwd=ROOT, check=False, stdout=subprocess.PIPE, text=True,
    )
    local.write_text(out.stdout)


def load_events(path: pathlib.Path) -> list[dict]:
    events = []
    if not path.exists():
        return events
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return events


def main() -> int:
    windows = json.loads((OUT / "windows.json").read_text())
    pull("/var/ossec/logs/alerts/alerts.json", OUT / "alerts.json")
    pull("/var/ossec/logs/archives/archives.json", OUT / "archives.json")
    alerts = load_events(OUT / "alerts.json")
    archives = load_events(OUT / "archives.json")

    results = []
    for tech in windows["techniques"]:
        lo = tech["t_start"] - 3
        hi = tech["t_end"] + GRACE_END
        extra = EXTRA_RULE_IDS.get(tech["id"], set())
        matched, window_alerts = [], []
        for a in alerts:
            try:
                ts = parse_ts(a["timestamp"])
            except (KeyError, ValueError):
                continue
            if not (lo <= ts <= hi):
                continue
            rule = a.get("rule", {})
            mitre = rule.get("mitre", {}).get("id", []) or []
            rid = str(rule.get("id", ""))
            rec = {
                "rule_id": rid,
                "level": rule.get("level"),
                "description": rule.get("description"),
                "mitre": mitre,
            }
            window_alerts.append(rec)
            if tech["base_id"] in mitre or tech["id"] in mitre or rid in extra:
                matched.append(rec)

        received = sum(
            1 for e in archives
            if e.get("agent", {}).get("name") == AGENT
            and _in(e, tech["t_start"] - 3, tech["t_end"] + 10)
        )
        results.append({
            **{k: tech[k] for k in (
                "id", "base_id", "tactic", "attack_name", "expect",
                "fim_paths", "exec", "note")},
            "matched_alerts": _dedup(matched),
            "window_alert_count": len(window_alerts),
            "siem_events_received": received,
        })
        print(f"collect: {tech['id']:<12} matched={len(matched)} "
              f"received={received}")

    (OUT / "results.json").write_text(json.dumps(
        {"runid": windows["runid"], "results": results}, indent=2))
    print(f"collect: wrote {OUT / 'results.json'}")
    return 0


def _in(event: dict, lo: float, hi: float) -> bool:
    try:
        return lo <= parse_ts(event["timestamp"]) <= hi
    except (KeyError, ValueError):
        return False


def _dedup(recs: list[dict]) -> list[dict]:
    seen, out = set(), []
    for r in recs:
        key = (r["rule_id"], r["description"])
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out


if __name__ == "__main__":
    sys.exit(main())
