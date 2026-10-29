#!/usr/bin/env python3
"""Turn a before/after pair of Trivy scans into a closure proof.

Vulnerability management is not "run a scanner"; it is find -> triage -> fix ->
prove. This script is the last step. It reads the scan of the target before
remediation and the scan after it, checks that each remediated finding is gone
and the deferred finding is still there, and writes the proof to a summary file.

The triage reasoning — why these three findings are fixed first and the fourth
is accepted — lives in docs/vuln-report.md. Here the findings are encoded so
the loop can verify itself: if a fix did not land, or if a deferred finding
quietly vanished (so the scan no longer reflects the image), the script exits
non-zero and `make vuln` fails.

Usage: assess.py <before.json> <after.json> <summary.json>
"""
from __future__ import annotations

import collections
import datetime
import json
import sys

# Each remediated finding names the packages it covers and one representative
# CVE that must be present before and absent after. The representative CVEs are
# older issues with released Ubuntu fixes, so the proof is stable even as
# Trivy's database (and the absolute counts) change from day to day.
REMEDIATED = [
    {
        "id": "openssl",
        "title": "OpenSSL runtime library outdated (libssl3)",
        "packages": ["libssl3"],
        "must_close": "CVE-2024-6119",
        "remediation": "Upgrade to libssl3t64 (renamed by the 64-bit time_t transition).",
        "why_first": "Network-reachable: every TLS listener links it. CVE-2024-6119 is a "
        "remotely triggerable crash in certificate name checks.",
    },
    {
        "id": "glibc",
        "title": "GNU C library outdated (libc6)",
        "packages": ["libc6", "libc-bin"],
        "must_close": "CVE-2024-2961",
        "remediation": "Upgrade libc6 and libc-bin to the current security release.",
        "why_first": "Reachable through countless code paths; CVE-2024-2961 (iconv) is a "
        "known building block of real exploit chains.",
    },
    {
        "id": "pam",
        "title": "PAM authentication modules outdated (libpam)",
        "packages": ["libpam-modules", "libpam-modules-bin", "libpam-runtime", "libpam0g"],
        "must_close": "CVE-2024-10963",
        "remediation": "Upgrade the libpam packages to the current security release.",
        "why_first": "PAM gates every login on an SSH-facing host; CVE-2024-10963 lets "
        "pam_access rules be bypassed.",
    },
]

# Deliberately not fixed in this round. It must stay present in the after-scan:
# that is what shows remediation was selective and that the re-scan still
# reflects the image.
DEFERRED = {
    "id": "gpgv",
    "title": "gpgv signature verifier outdated",
    "packages": ["gpgv"],
    "must_remain": "CVE-2025-68973",
    "reason": "HIGH by CVSS, but gpgv only runs while apt verifies repository "
    "signatures over TLS — not reachable from the network at runtime. Accepted "
    "this round and scheduled with the next full patch.",
}


def load(path):
    """Return {(cve, pkg): record} for the OS-package vulnerabilities in a Trivy report."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    out = {}
    for result in doc.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            out[(v["VulnerabilityID"], v["PkgName"])] = v
    return out


def severities(vulns):
    counts = collections.Counter(v["Severity"] for v in vulns.values())
    return {s: counts.get(s, 0) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN") if counts.get(s)}


def closed_cves(before, after, packages):
    """CVEs on these packages that were present before and are absent after."""
    pkgs = set(packages)
    out = sorted(
        {cve for (cve, pkg) in before if pkg in pkgs}
        - {cve for (cve, pkg) in after if pkg in pkgs}
    )
    return out


def present(vulns, cve):
    return any(c == cve for (c, _pkg) in vulns)


def evaluate(before, after):
    """Return (summary, failures) for a before/after pair of {(cve,pkg): record} maps."""
    findings = []
    failures = []

    for f in REMEDIATED:
        rep = f["must_close"]
        was = present(before, rep)
        still = present(after, rep)
        closed = closed_cves(before, after, f["packages"])
        ok = was and not still
        if not ok:
            failures.append(
                f"{f['id']}: expected {rep} present before and gone after "
                f"(before={was}, after={still})"
            )
        findings.append(
            {
                "id": f["id"],
                "title": f["title"],
                "packages": f["packages"],
                "remediation": f["remediation"],
                "why_first": f["why_first"],
                "representative_cve": rep,
                "cves_closed": closed,
                "closed_count": len(closed),
                "status": "closed" if ok else "NOT CLOSED",
            }
        )

    rep = DEFERRED["must_remain"]
    deferred_ok = present(before, rep) and present(after, rep)
    if not deferred_ok:
        failures.append(
            f"deferred {DEFERRED['id']}: expected {rep} present before and after "
            "(a deferred finding that vanished means the re-scan no longer reflects the image)"
        )
    deferred = {
        **{k: DEFERRED[k] for k in ("id", "title", "packages", "reason")},
        "representative_cve": rep,
        "still_present_after": present(after, rep),
    }

    summary = {
        "scanned_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "before": {"total": len(before), "by_severity": severities(before)},
        "after": {"total": len(after), "by_severity": severities(after)},
        "remediated": findings,
        "deferred": deferred,
        "proven": not failures,
    }
    return summary, failures


def main():
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    before_path, after_path, summary_path = sys.argv[1:4]
    before = load(before_path)
    after = load(after_path)
    summary, failures = evaluate(before, after)
    findings = summary["remediated"]
    deferred = summary["deferred"]

    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")

    # Human-readable summary.
    print(f"\nTarget scanned before/after remediation")
    print(f"  before: {len(before):4d} findings  {severities(before)}")
    print(f"  after:  {len(after):4d} findings  {severities(after)}\n")
    print("Remediated this round:")
    for f in findings:
        mark = "OK " if f["status"] == "closed" else "!! "
        print(f"  {mark}{f['id']:8s} {f['closed_count']:3d} CVEs closed "
              f"(incl. {f['representative_cve']})")
    print(f"\nDeferred (risk-accepted): {deferred['id']} "
          f"{deferred['representative_cve']} "
          f"{'still present' if deferred['still_present_after'] else 'MISSING'}")
    print(f"\nProof written to {summary_path}")

    if failures:
        print("\nFAIL: closure not proven:", file=sys.stderr)
        for line in failures:
            print("  - " + line, file=sys.stderr)
        return 1
    print("\nPASS: three findings closed, deferred finding intact.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
