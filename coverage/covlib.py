"""Shared helpers for the detection-coverage assessment.

Kept separate from the scripts so the scorer can be unit-tested without a
running lab.
"""
from __future__ import annotations

import pathlib
import re
import yaml

VERDICTS = ("detected", "logged", "blind")

# ATT&CK tactic short name -> the verdict colours used in the Navigator layer.
VERDICT_COLOR = {
    "detected": "#2e9e54",   # green: a rule fired
    "logged": "#d9a406",     # amber: a sensor saw it, no rule fired
    "blind": "#c0392b",      # red: nothing saw it
}


def load_spec(path: str | pathlib.Path) -> dict:
    """Load techniques.yaml."""
    return yaml.safe_load(pathlib.Path(path).read_text())


def base_id(technique_id: str) -> str:
    """T1087.001 -> T1087. Wazuh tags alerts with the base technique id."""
    return technique_id.split(".")[0]


def substitute(command: str, args: dict) -> str:
    """Fill an atomic's #{name} input arguments, as Invoke-Atomic does."""
    def repl(m: re.Match) -> str:
        key = m.group(1)
        if key not in args:
            raise KeyError(f"no value for input argument #{{{key}}}")
        return str(args[key])

    return re.sub(r"#\{([^}]+)\}", repl, command)


def apply_runid(args: dict, runid_args: list[str] | None, runid: str) -> dict:
    """Append the run id to the named args so repeated runs do not collide."""
    args = dict(args)
    for key in runid_args or []:
        args[key] = f"{args[key]}_{runid}"
    return args


def verify_atomic(tech: dict, art_root: pathlib.Path) -> None:
    """Assert techniques.yaml's copy of an atomic matches the pinned ART repo.

    Proves the emulated commands are the real atomics, not something invented.
    """
    atomic = tech.get("atomic")
    if not atomic:
        return  # e.g. the T1110 probe, which has no ART atomic
    tid = tech["id"]
    path = art_root / tid / f"{tid}.yaml"
    doc = yaml.safe_load(path.read_text())
    for test in doc["atomic_tests"]:
        if test["auto_generated_guid"] == atomic["guid"]:
            if test["executor"]["command"] != atomic["command"]:
                raise ValueError(
                    f"{tid} {atomic['guid']}: command in techniques.yaml does "
                    f"not match the pinned ART repo"
                )
            return
    raise ValueError(f"{tid}: atomic {atomic['guid']} not found in pinned ART repo")


def classify(tech: dict, matched_alerts: list, syscheck_dirs: list[str]) -> dict:
    """Decide detected / logged / blind for one technique from its evidence.

    - detected: a Wazuh rule fired for this technique inside its run window.
    - logged:   no rule fired, but a host sensor records the behaviour -- here,
                a file the technique touches is inside the agent's FIM scope.
    - blind:    no rule fired and no sensor on the host captures the behaviour.
    """
    if matched_alerts:
        verdict = "detected"
        reason = "rule(s) " + ", ".join(
            sorted({str(a["rule_id"]) for a in matched_alerts})
        ) + " fired in the run window"
    elif _fim_covers(tech.get("fim_paths"), syscheck_dirs):
        verdict = "logged"
        reason = "file is in the agent's FIM scope, but FIM is a scheduled scan, so no alert fired in the window"
    else:
        verdict = "blind"
        reason = "no rule fired and no host sensor records this behaviour"
    return {"verdict": verdict, "reason": reason}


def _fim_covers(paths: list[str] | None, syscheck_dirs: list[str]) -> bool:
    if not paths:
        return False
    for p in paths:
        if any(p == d or p.startswith(d.rstrip("/") + "/") for d in syscheck_dirs):
            return True
    return False
