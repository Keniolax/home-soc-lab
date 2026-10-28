# Incident report: HTTP command-and-control on a domain workstation

**Framework:** NIST SP 800-61 Rev. 2 · **Severity:** High · **Status:** Contained
(documented) · **Analyst:** home-soc-lab

`make ir` rebuilds the timeline in this report from the evidence. Every fact
below comes from the capture; the facts block is
[`docs/evidence/ir/timeline.json`](evidence/ir/timeline.json).

## Summary

A Windows workstation, `DESKTOP-RNVO9AT` (172.17.0.99), in the `bepositive.com`
Active Directory domain, was beaconing to an external command-and-control (C2)
server at **79.124.78.197** over HTTP. The host checked in to `POST /foots.php`
under a hardcoded fake Internet Explorer User-Agent, about once a minute, for the
whole hour of captured traffic. This is MITRE ATT&CK
[T1071.001](https://attack.mitre.org/techniques/T1071/001/), Application Layer
Protocol: Web. The host was already infected when the capture began, so the
initial compromise is earlier than any evidence here.

## Scope of this report

This is a network-forensic incident response on captured evidence — the week-6
capture that the lab's network sensor detected. Detection, analysis and the IOC
extraction are **executed** on the real evidence and reproduced by `make ir`. The
infected host is a Windows machine owned by a third party (the capture is a public
training exercise), so **containment, eradication and recovery are written as a
specific playbook**, not performed on someone else's machine. Where the lab can
enforce a control itself — the Suricata rules that detect this C2 — it does.

## 1. Preparation

What was already in place when the incident was found, built over weeks 1–6:

- A Wazuh SIEM collecting host logs and, since week 6, network-sensor alerts.
- A network sensor (Suricata + Zeek) over the traffic.
- Authored detections for host persistence and for this class of network C2.
- A pinned, reproducible lab, so any finding can be rebuilt and checked.

Preparation is what turns "something looks wrong" into an answer in minutes. The
detection that opened this case existed before the case did.

## 2. Detection and analysis

**How it was detected.** The network sensor's Suricata rules fired on the C2
traffic and the alerts reached the SIEM (rule 86601). In parallel, the week-6
threat hunt found the same host from Zeek metadata alone: one internal host
contacting one external address far more than any other, by raw IP, with no DNS
lookup.

**Timeline** (UTC, rebuilt by `ir/timeline.py`):

| Time | Event | Source |
|---|---|---|
| 17:32:31 | Capture begins; baseline traffic from 172.17.0.99, no C2 yet | conn.log |
| 17:35:06 | First C2 contact: 172.17.0.99 → 79.124.78.197 (already beaconing) | conn.log |
| 17:35:07 | First check-in: `POST /foots.php` to the C2 | http.log |
| 17:35:07 | First network detection: Suricata rule fires on the C2 traffic | eve.json |
| 17:35:11 | C2 registration: `GET /index.php?id=&subid=qIOuKk7U` | http.log |
| 18:31:52 | Last C2 activity: still beaconing to 79.124.78.197 | conn.log |
| 18:31:52 | Capture ends | conn.log |

Note the order: the first `POST /foots.php` check-in (17:35:07) comes **before**
the `/index.php` registration (17:35:11). The intuitive "register, then check in"
order is not what happened; the evidence settles it.

**Scope.** One host, 172.17.0.99. Its other traffic — SMB, Kerberos, LDAP, DNS —
all goes to 172.17.0.17, the domain controller, which is ordinary domain-member
activity, not lateral movement. No second infected host appears in the capture.

**What the host sent.** Across all 50 HTTP requests to the C2, the host uploaded
**62 bytes** of request body in total. These are check-in beacons, not bulk data
transfer; no large upload of stolen data is visible in this capture.

**Severity: High.** Live C2 on a domain-joined workstation is a foothold an
attacker can use at any time to steal credentials or move laterally. That none of
that is visible yet does not lower the severity — the channel is open.

## 3. Containment, eradication and recovery

The playbook, with this incident's indicators filled in:

**Contain (immediately).**
- Block the C2 at the perimeter: deny all traffic to **79.124.78.197**. The lab
  enforces the detection side of this itself — the Suricata rules in
  [`network/suricata/local.rules`](../network/suricata/local.rules) alert on this
  C2 by address, by User-Agent, and by the raw-IP POST behaviour; in an inline
  (IPS) deployment the same rules drop it.
- Isolate 172.17.0.99 from the network (host quarantine), keeping it powered on
  for memory capture.
- Disable the logged-in user's domain account until triage is done, since the C2
  may already have the credentials.

**Eradicate.**
- Reimage 172.17.0.99 from a known-good image. Commodity loaders pull further
  payloads, so cleaning in place is not trusted.
- Reset the credentials of every account used on the host, and any domain
  credential it could reach, including Kerberos tickets.

**Recover.**
- Return the host to service only after reimaging and a clean scan.
- Watch for re-beaconing to 79.124.78.197 and to the IOCs below for at least a
  week; the detections from week 6 do this.

## 4. Post-incident activity

### What should change

- **The host had no process or command logging.** The network sensor caught the
  C2, but nothing on the host would have shown which process opened the
  connection. An endpoint sensor (Sysmon for Windows; auditd/Falco for Linux)
  is the gap to close — the same gap week 4 and week 5 recorded.
- **The capture starts after infection.** With no record of initial access, the
  root cause is a guess. Earlier and broader capture (or endpoint telemetry)
  would catch the delivery, not just the beacon.

### AI drafting vs. verification

An LLM drafted a first timeline before any evidence was checked
([`../ir/ai-draft-timeline.md`](../ir/ai-draft-timeline.md)). It read fluently and
was mostly wrong. Each claim, checked against the capture:

| AI claim | Verdict | What the evidence says |
|---|---|---|
| Initial access via a phishing email with a macro | **Unconfirmed** | The capture begins after infection. No email, download or macro is in it. |
| Malware is Amadey | **Unconfirmed** | The `/foots.php` + `subid` URIs and the fake MSIE User-Agent are suggestive, but the network capture alone does not identify the family. Stated as a lead, not a fact. |
| Exploited CVE-2023-21674 for SYSTEM | **Unsupported** | No exploit traffic is present, and that CVE is a local privilege-escalation bug unrelated to this HTTP C2. A plausible-looking but invented detail. |
| Registration first, then check-ins | **Contradicted** | The first `POST /foots.php` (17:35:07) precedes the `/index.php` registration (17:35:11). |
| Beacons every 60 seconds | **Contradicted** | Mean interval 50.8 s, with jitter from a few seconds to ~3 minutes. Not a fixed 60 s. |
| Exfiltrated credentials and browser data to the C2 | **Unsupported** | Total request-body uploaded to the C2 is 62 bytes. These are beacons, not bulk exfiltration. |
| Lateral movement across SMB to other hosts | **Contradicted** | All SMB/Kerberos/LDAP traffic goes to the domain controller (172.17.0.17); it is normal domain activity. No second host is touched. |
| Dwell time about 57 minutes | **Misleading** | 57 minutes is the capture window. The host was already beaconing at the start, so the true dwell time is unknown and longer. |
| C2 at 79.124.78.197 over HTTP, `POST /foots.php` | **Confirmed** | conn.log and http.log. |
| Hardcoded fake MSIE/Trident User-Agent | **Confirmed** | http.log; the UA claims IE 7 on Windows 10, which never shipped. |

Eight of ten claims were wrong, unsupported or misleading, and every one of them
was plausible. The model invented a CVE, a malware family, an exfiltration, a
lateral-movement phase and a precise beacon interval — the kind of specific,
confident detail that reads as expertise and would have sent responders down
wrong paths. **AI is useful to draft the shape of a timeline; every line has to
be checked against raw evidence before it enters a report.** That is why
`ir/timeline.py` builds the timeline from the logs, and why each line in the
table above cites what the evidence actually shows.

## Appendix: indicators of compromise

| Type | Indicator |
|---|---|
| C2 server | `79.124.78.197` (TCP 80, HTTP) |
| C2 endpoints | `POST /foots.php`, `GET /index.php?id=&subid=qIOuKk7U` |
| Malware User-Agent | `Mozilla/4.0 (compatible; MSIE 7.0; ... Trident/7.0; ...)` |
| Infected host | `172.17.0.99` (`DESKTOP-RNVO9AT`, domain `bepositive.com`) |

## Reproduce

```bash
make up    # the lab (for the SIEM-side detection)
make ir    # fetch the capture, run the sensors, rebuild this timeline
```

`make ir` writes [`docs/evidence/ir/timeline.json`](evidence/ir/timeline.json).
The capture and sensors are pinned, so the timeline is the same every run.
