#!/usr/bin/env python3
"""Classify each technique and write the coverage artifacts.

Reads tmp/coverage/results.json and tmp/coverage/syscheck.json, assigns each
technique detected / logged / blind, and writes:
  - coverage/navigator/coverage-layer.json   (ATT&CK Navigator layer, the heatmap)
  - docs/evidence/coverage/matrix.md          (the coverage matrix)
  - docs/evidence/coverage/summary.json       (counts for the write-up)
  - docs/evidence/coverage/results.json       (the raw run evidence)
"""
from __future__ import annotations

import json
import pathlib
import sys

import covlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
TMP = ROOT / "tmp/coverage"
NAV = ROOT / "coverage/navigator"
EV = ROOT / "docs/evidence/coverage"

ATTACK_VERSION = "17"
VERDICT_LABEL = {
    "detected": "Detected (a rule fired)",
    "logged": "Logged, not detected",
    "blind": "Blind (no telemetry)",
}


def build_layer(scored: list[dict]) -> dict:
    techniques = []
    for s in scored:
        techniques.append({
            "techniqueID": s["id"],
            "tactic": s["tactic"],
            "color": covlib.VERDICT_COLOR[s["verdict"]],
            "comment": f"{VERDICT_LABEL[s['verdict']]}: {s['reason']}",
            "enabled": True,
            "metadata": [
                {"name": "name", "value": s["attack_name"]},
                {"name": "verdict", "value": s["verdict"]},
                {"name": "emulated", "value": s["exec"][:220]},
                {"name": "rules fired", "value":
                    ", ".join(f"{a['rule_id']} (L{a['level']})"
                              for a in s["matched_alerts"]) or "none"},
            ],
            "showSubtechniques": False,
        })
    return {
        "name": "home-soc-lab detection coverage (week 4)",
        "versions": {"attack": ATTACK_VERSION, "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "What the home-soc-lab SIEM detects, logs, or is blind to "
                       "across 14 emulated Linux ATT&CK techniques. Green: a rule "
                       "fired. Amber: a sensor recorded it but no rule fired. "
                       "Red: nothing on the host saw it.",
        "techniques": techniques,
        "legendItems": [
            {"label": VERDICT_LABEL["detected"], "color": covlib.VERDICT_COLOR["detected"]},
            {"label": VERDICT_LABEL["logged"], "color": covlib.VERDICT_COLOR["logged"]},
            {"label": VERDICT_LABEL["blind"], "color": covlib.VERDICT_COLOR["blind"]},
        ],
        "sorting": 0,
        "hideDisabled": False,
        "showTacticRowBackground": True,
        "tacticRowBackground": "#205b8f",
        "selectTechniquesAcrossTactics": True,
    }


def build_matrix(scored: list[dict]) -> str:
    glyph = {"detected": "🟢 detected", "logged": "🟡 logged", "blind": "🔴 blind"}
    lines = [
        "# Detection coverage matrix",
        "",
        "One row per emulated technique. Verdict is what the SIEM did during the",
        "technique's run window.",
        "",
        "| Technique | ATT&CK | Tactic | Verdict | Rules fired |",
        "|---|---|---|---|---|",
    ]
    for s in scored:
        rules = ", ".join(f"{a['rule_id']} (L{a['level']})"
                          for a in s["matched_alerts"]) or "—"
        lines.append(
            f"| {s['attack_name']} | {s['id']} | {s['tactic']} | "
            f"{glyph[s['verdict']]} | {rules} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    data = json.loads((TMP / "results.json").read_text())
    syscheck = json.loads((TMP / "syscheck.json").read_text())["dirs"]

    scored = []
    mismatches = []
    for r in data["results"]:
        verdict = covlib.classify(r, r["matched_alerts"], syscheck)
        s = {**r, **verdict}
        scored.append(s)
        if s["verdict"] != r["expect"]:
            mismatches.append(f"{r['id']}: expected {r['expect']}, got {s['verdict']}")

    counts = {v: sum(1 for s in scored if s["verdict"] == v) for v in covlib.VERDICTS}
    blind_by_tactic: dict[str, int] = {}
    for s in scored:
        if s["verdict"] == "blind":
            blind_by_tactic[s["tactic"]] = blind_by_tactic.get(s["tactic"], 0) + 1

    NAV.mkdir(parents=True, exist_ok=True)
    EV.mkdir(parents=True, exist_ok=True)
    (NAV / "coverage-layer.json").write_text(json.dumps(build_layer(scored), indent=2))
    (EV / "matrix.md").write_text(build_matrix(scored))
    (EV / "results.json").write_text(json.dumps(data, indent=2))
    (EV / "summary.json").write_text(json.dumps({
        "runid": data["runid"],
        "total": len(scored),
        "counts": counts,
        "blind_by_tactic": blind_by_tactic,
        "verdicts": {s["id"]: s["verdict"] for s in scored},
    }, indent=2))

    print(f"score: {counts['detected']} detected, {counts['logged']} logged, "
          f"{counts['blind']} blind (of {len(scored)})")
    if mismatches:
        print("score: verdicts differing from the documented expectation:")
        for m in mismatches:
            print(f"       {m}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
