#!/usr/bin/env python3
"""Run each technique's atomic on the victim and record its time window.

Reads coverage/techniques.yaml, verifies every atomic against the pinned ART
clone, runs them in order on the victim with a gap between each, and writes
the run windows to tmp/coverage/windows.json for the collector.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import time

import covlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
ART = ROOT / "tmp/coverage/atomic-red-team/atomics"
OUT = ROOT / "tmp/coverage"
GAP_SECONDS = 8          # quiet gap between techniques, keeps windows apart
DEFAULT_TIMEOUT = 60


def compose(*args: str, check: bool = True, capture: bool = False):
    cmd = ["docker", "compose", *args]
    return subprocess.run(
        cmd, cwd=ROOT, check=check,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
        text=True,
    )


def victim(cmd: str, executor: str = "sh", timeout: int = DEFAULT_TIMEOUT) -> None:
    """Run a command inside the victim, capped by a container-side timeout."""
    shell = "bash" if executor == "bash" else "sh"
    compose(
        "exec", "-T", "victim",
        "timeout", str(timeout), shell, "-c", cmd,
        check=False, capture=True,
    )


def run_probe(count: int, runid: str) -> str:
    user = f"cov-brute-{runid}"
    compose(
        "--profile", "test", "run", "--rm", "--no-deps",
        "probe", "victim", user, str(count),
        check=False, capture=True,
    )
    return user


def main() -> int:
    spec = covlib.load_spec(ROOT / "coverage/techniques.yaml")
    runid = time.strftime("%H%M%S")
    OUT.mkdir(parents=True, exist_ok=True)

    # Verify every atomic against the pinned ART repo before running anything.
    for tech in spec["techniques"]:
        covlib.verify_atomic(tech, ART)
    print(f"emulate: verified {len(spec['techniques'])} techniques against pinned ART")

    records = []
    for tech in spec["techniques"]:
        tid = tech["id"]
        timeout = int(tech.get("timeout", DEFAULT_TIMEOUT))
        t_start = time.time()

        if tech.get("probe"):
            indicator = run_probe(int(tech["args"]["count"]), runid)
            exec_cmd = f"(lab ssh-probe: {tech['args']['count']} failed logins as {indicator})"
        else:
            args = covlib.apply_runid(tech["args"], tech.get("runid_args"), runid)
            if tech.get("setup"):
                victim(covlib.substitute(tech["setup"], args), timeout=timeout)
            exec_cmd = covlib.substitute(tech["atomic"]["command"], args)
            victim(exec_cmd, executor=tech["atomic"]["executor"], timeout=timeout)
            indicator = args.get("username")

        t_end = time.time()
        print(f"emulate: {tid:<12} {tech['attack_name']}")
        records.append({
            "id": tid,
            "base_id": covlib.base_id(tid),
            "tactic": tech["tactic"],
            "attack_name": tech["attack_name"],
            "expect": tech["expect"],
            "fim_paths": tech.get("fim_paths"),
            "indicator": indicator,
            "note": tech.get("note"),
            "exec": exec_cmd.strip(),
            "t_start": t_start,
            "t_end": t_end,
        })

        if tech.get("cleanup"):
            args = covlib.apply_runid(tech["args"], tech.get("runid_args"), runid)
            victim(covlib.substitute(tech["cleanup"], args), timeout=30)
        time.sleep(GAP_SECONDS)

    (OUT / "windows.json").write_text(json.dumps(
        {"runid": runid, "techniques": records}, indent=2))
    print(f"emulate: wrote {OUT / 'windows.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
