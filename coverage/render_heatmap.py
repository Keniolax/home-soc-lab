#!/usr/bin/env python3
"""Render the coverage Navigator layer to a PNG heatmap.

Groups techniques by ATT&CK tactic and colours each by verdict. A letter in the
corner (D/L/B) repeats the verdict, so the chart does not rely on colour alone.
The Navigator layer JSON stays the portable source of truth.
"""
from __future__ import annotations

import json
import pathlib
import textwrap

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

ROOT = pathlib.Path(__file__).resolve().parent.parent
LAYER = ROOT / "coverage/navigator/coverage-layer.json"
OUT = ROOT / "docs/img/coverage-heatmap.png"

TACTIC_ORDER = [
    "credential-access", "execution", "persistence",
    "defense-evasion", "discovery",
]
TACTIC_TITLE = {
    "credential-access": "Credential\nAccess", "execution": "Execution",
    "persistence": "Persistence", "defense-evasion": "Defense\nEvasion",
    "discovery": "Discovery",
}
GLYPH = {"detected": "D", "logged": "L", "blind": "B"}
INK = "#1b2733"


def meta(t: dict, name: str) -> str:
    for m in t.get("metadata", []):
        if m["name"] == name:
            return m["value"]
    return ""


def main() -> int:
    layer = json.loads(LAYER.read_text())
    by_tactic: dict[str, list[dict]] = {k: [] for k in TACTIC_ORDER}
    for t in layer["techniques"]:
        by_tactic.setdefault(t["tactic"], []).append(t)

    cols = [k for k in TACTIC_ORDER if by_tactic.get(k)]
    rows = max(len(by_tactic[c]) for c in cols)
    cw, ch = 3.0, 1.15
    fig_w = len(cols) * cw + 0.5
    fig_h = rows * ch + 2.4
    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    ax.set_xlim(0, len(cols) * cw)
    ax.set_ylim(0, rows * ch + 1.8)
    ax.axis("off")

    counts = {"detected": 0, "logged": 0, "blind": 0}
    for ci, tactic in enumerate(cols):
        x = ci * cw
        ax.text(x + cw / 2, rows * ch + 1.35, TACTIC_TITLE[tactic],
                ha="center", va="center", fontsize=12, fontweight="bold",
                color="white",
                bbox=dict(boxstyle="round,pad=0.4", fc="#205b8f", ec="none"))
        for ri, t in enumerate(by_tactic[tactic]):
            verdict = meta(t, "verdict")
            counts[verdict] = counts.get(verdict, 0) + 1
            y = (rows - 1 - ri) * ch
            ax.add_patch(FancyBboxPatch(
                (x + 0.08, y + 0.08), cw - 0.16, ch - 0.16,
                boxstyle="round,pad=0.02,rounding_size=0.08",
                fc=t["color"], ec="white", lw=1.5))
            ax.text(x + 0.22, y + ch - 0.28, t["techniqueID"],
                    fontsize=9.5, fontweight="bold", color="white", va="center")
            ax.text(x + cw - 0.22, y + ch - 0.28, GLYPH.get(verdict, "?"),
                    fontsize=11, fontweight="bold", color="white",
                    ha="right", va="center")
            name = "\n".join(textwrap.wrap(_name(t), 34)[:2])
            ax.text(x + 0.22, y + 0.34, name, fontsize=8, color="white", va="center")

    fig.suptitle("home-soc-lab detection coverage — MITRE ATT&CK (week 4)",
                 fontsize=15, fontweight="bold", color=INK, y=0.99)
    total = sum(counts.values())
    sub = (f"{counts['detected']} detected   ·   {counts['logged']} logged, not detected"
           f"   ·   {counts['blind']} blind     (of {total} techniques emulated)")
    ax.text(len(cols) * cw / 2, rows * ch + 0.5, sub, ha="center",
            fontsize=10.5, color=INK)

    handles = [
        plt.Line2D([0], [0], marker="s", linestyle="", markersize=12,
                   markerfacecolor=c, markeredgecolor="white",
                   label=f"{lab}")
        for lab, c in [("Detected — a rule fired (D)", "#2e9e54"),
                       ("Logged, not detected (L)", "#d9a406"),
                       ("Blind — no telemetry (B)", "#c0392b")]
    ]
    ax.legend(handles=handles, loc="lower center", ncol=3,
              bbox_to_anchor=(0.5, -0.04 / fig_h), frameon=False, fontsize=9.5)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT, dpi=200, bbox_inches="tight", facecolor="white")
    print(f"render: wrote {OUT}")
    return 0


def _name(t: dict) -> str:
    # Short, readable label: the ATT&CK technique name, minus any "X: Y" prefix.
    name = meta(t, "name") or t["techniqueID"]
    return name.split(": ")[-1]


if __name__ == "__main__":
    import sys
    sys.exit(main())
