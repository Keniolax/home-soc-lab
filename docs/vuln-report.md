# Vulnerability assessment: the lab server image

`make vuln` runs one full round of vulnerability management on a lab server
image: scan, triage, fix three findings, then scan again to prove they are
closed. The point is the last step. A scan report lists problems; this report
shows three of them fixed, with a before-and-after scan to prove it.

## What was scanned

The target is an Ubuntu 24.04 server image pinned to an old build
(`ubuntu:noble-20240225`, by digest). It is deliberately out of date, the way a
real server drifts between patch windows. The lab's victim runs the same
operating system and the same libraries, so these findings are the ones a
credentialed scan of the lab host would raise.

The scanner is Trivy. It reads the installed package versions and checks each
one against the Ubuntu security feed. Nessus and OpenVAS, the two scanners the
course names, do not run on the build host: Nessus needs an emailed activation
code and OpenVAS's images and feed are not reachable here. Trivy does the same
job for operating-system packages, so the loop is built on it. A real programme
runs more than one scanner, because each misses things the others catch; this
lab runs one, and that is its main limit.

## Scan: what the first scan found

| Severity | Findings |
|---|---|
| High | 3 |
| Medium | 205 |
| Low | 53 |
| **Total** | **261** |

261 findings is too many to fix at once, and most do not matter much. Triage
decides the order.

## Triage: rank by what an attacker can reach, not by score

A CVSS score rates a vulnerability on its own. It does not know whether the
weak code runs on this host, or whether an attacker can reach it. So the score
sets the starting point, and reachability on this host sets the order.

| Finding | Package | Worst severity | Reachable here? | Decision |
|---|---|---|---|---|
| OpenSSL out of date | `libssl3` | High | Yes — every TLS connection runs this code | **Fix now** |
| glibc out of date | `libc6`, `libc-bin` | Medium | Yes — almost every program links it; the `iconv` flaw (CVE-2024-2961) is a known exploit building block | **Fix now** |
| PAM out of date | `libpam*` | Medium | Yes — PAM checks every SSH login; CVE-2024-10963 lets an access rule be bypassed | **Fix now** |
| gpgv out of date | `gpgv` | High | No — gpgv only runs while `apt` checks a repository signature over TLS | **Defer** |

The gpgv finding is the lesson. By score it is High, higher than the glibc and
PAM findings. By reach it is the weakest of the four: nothing on the network
can send data to gpgv, because it only reads signatures that `apt` already
fetched over a trusted channel. So it is accepted this round and left for the
next full patch. Two Medium findings that an attacker can reach are fixed
before one High finding that it cannot.

## Fix: what was changed

The three chosen findings are all fixed the same way, by installing the
Ubuntu security update for the package:

- **OpenSSL.** Upgrade `libssl3` to the current release. Ubuntu's 64-bit
  `time_t` change renamed the package to `libssl3t64`, so the fix arrives
  under the new name. Installed version `3.0.13-0ubuntu3.16`.
- **glibc.** Upgrade `libc6` and `libc-bin` to `2.39-0ubuntu8.9`.
- **PAM.** Upgrade the `libpam` packages to `1.5.3-5ubuntu5.6`.

Only these packages are upgraded. gpgv and the other deferred packages are left
as they were, so the second scan shows exactly what the fix changed and nothing
else.

## Re-scan: proof the findings are closed

| Severity | Before | After |
|---|---|---|
| High | 3 | 1 |
| Medium | 205 | 137 |
| Low | 53 | 20 |
| **Total** | **261** | **158** |

The three findings are closed:

- **OpenSSL:** 43 CVEs gone, including CVE-2024-6119 (a remote crash in
  certificate name checks).
- **glibc:** 24 CVEs gone, including CVE-2024-2961.
- **PAM:** CVE-2024-10963 and CVE-2025-6020 gone.

The one High finding left is gpgv (CVE-2025-68973), the finding that was
deferred on purpose. It is still there because it was not fixed. That is the
check that the scan is honest: `vuln/assess.py` fails the run if a fixed finding
is still present, and it also fails if the deferred finding disappears, because
that would mean the second scan no longer matches the image that was shipped.

The full before-and-after proof is in
[`docs/evidence/vuln/summary.json`](evidence/vuln/summary.json).

## Why the proof can fail

A test that cannot fail proves nothing. Build the target without the fix and
scan it: the three findings are still there, and `assess.py` reports the round
as not proven and exits with an error. The pass in a normal run is earned.

## Reproduce it

```bash
make vuln
```

It builds the target unpatched and scans it, builds it again with the three
fixes and scans that, then checks the result. Trivy's database changes every
day, so the exact totals will drift, but the proof is written against specific
CVE identifiers that are present before and gone after, so the result holds.
