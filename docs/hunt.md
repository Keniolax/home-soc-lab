# Network detection and threat hunting

`make hunt` adds a network sensor to the lab and runs one threat hunt with it.
Week 4's coverage run found the lab blind to the network: it read host logs only,
so a port scan, command-and-control traffic and data theft all passed unseen.
This closes that gap. It reads a real malicious capture with Suricata and Zeek,
ships the Suricata alerts to the SIEM, and hunts the capture for a
command-and-control (C2) channel, from a hypothesis to a list of indicators.

## The capture

The capture is a 2024-09-04 traffic-analysis exercise from
[malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/2024/09/04/index.html):
about an hour of traffic from one Windows host, `DESKTOP-RNVO9AT` (172.17.0.99),
in an Active Directory domain, `bepositive.com`. The host is already infected
when the capture starts.

A capture is evidence, not a program. Nothing in it is run. `network/fetch-pcap.sh`
downloads the pinned file into `pcaps/` (which git ignores), checks it by SHA-256,
and extracts the one `.pcap` the zip holds. No sample is in the zip, and none is
run.

## The two sensors

A network sensor turns packets into records a detection or a hunt can read. The
lab runs two, both over the capture file, offline:

- **Suricata** is a signature engine. It matches each packet against rules and
  writes an alert when one fires. The lab's rules are in
  [`network/suricata/local.rules`](../network/suricata/local.rules). Suricata
  writes `eve.json`; the victim's Wazuh agent reads it and ships the alerts to
  the manager, so the **SIEM** sees the network sensor. This is the sensor the
  coverage run said was missing.
- **Zeek** is a metadata engine. It writes one row per connection (`conn.log`),
  per DNS query (`dns.log`), per HTTP request (`http.log`), per TLS handshake
  (`ssl.log`), and more. It raises no alerts. The **hunt** queries these.

Signatures catch what you already know to look for. Metadata lets you find what
you do not. A hunt needs the second.

## The hunt

A hunt starts from a hypothesis about how an attacker behaves, not from scrolling
the logs. `network/hunt.py` runs this one and prints each step.

**Hypothesis.** A host inside the network is infected and beaconing to an external
C2 server. If so, one internal host will contact one external address far more
than any other, probably over HTTP, probably by raw IP with no DNS lookup, and
send POST requests back to it.

**Query 1 — who talks to one outside address the most?** Group Zeek's `conn.log`
by internal host and external address, and count. One pair dwarfs the rest:
172.17.0.99 → 79.124.78.197, 68 connections, where the next is 8. That is the
shape of a beacon: the same call home, again and again.

**Query 2 — how is that address reached?** Its only HTTP `Host` header is the
address itself, `79.124.78.197`, and that address is never returned as a DNS
answer anywhere in the capture. The malware skips name resolution and calls a
hardcoded IP. A browser never does this.

**Query 3 — what does the conversation look like?** 49 of 50 requests are POSTs,
48 of them to `/foots.php`, with one `GET /index.php?id=&subid=qIOuKk7U` that
looks like a registration. Every request carries the same User-Agent:

```
Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0;
.NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729)
```

That string claims to be Internet Explorer 7 on Windows 10 — a combination that
never shipped. It is hardcoded in the malware.

**Finding.** 172.17.0.99 is beaconing to 79.124.78.197:80 over HTTP: 50 requests
over 57 minutes, a mean gap of about 51 seconds, to a raw IP with no DNS, POSTing
to `/foots.php` under a fake User-Agent. This is MITRE ATT&CK
[T1071.001](https://attack.mitre.org/techniques/T1071/001/), Application Layer
Protocol: Web.

## IOCs

The hunt writes these to [`docs/evidence/hunt/iocs.json`](evidence/hunt/iocs.json).

| Type | Indicator |
|---|---|
| C2 server | `79.124.78.197` (TCP 80, HTTP) |
| C2 endpoints | `POST /foots.php`, `GET /index.php?id=&subid=qIOuKk7U` |
| Malware User-Agent | `Mozilla/4.0 (compatible; MSIE 7.0; ... Trident/7.0; ...)` |
| Infected host | `172.17.0.99` (`DESKTOP-RNVO9AT`, domain `bepositive.com`) |
| Behaviour | HTTP beacon to a raw IP, no DNS, ~51 s interval, 57 min |

## Into the SIEM

The three Suricata rules show the three kinds of network detection, from the one
that breaks soonest to the one that lasts longest:

1. **IOC / reputation** — the C2 address itself. Precise, but dead the moment the
   attacker moves to a new server.
2. **Threat intelligence** — the hardcoded User-Agent. Catches the family wherever
   its C2 moves, until the malware author changes the string.
3. **Behaviour** — an HTTP POST whose `Host` header is a bare IP. Describes what
   this kind of malware must do, not one address it happens to use, so it catches
   families this hunt has never seen.

All three fire on the capture, and the manager's built-in Suricata ruleset raises
rule 86601, "Suricata: Alert", for each one. `network/check-siem.sh` confirms the
alerts reached the manager, so the network sensor is wired into the SIEM, not
just writing to a file.

## Run it

```bash
make up      # the lab, with the victim agent now reading the sensor's alerts
make hunt    # fetch the capture, run the sensors, hunt, confirm the SIEM alert
```

`make hunt` prints the hunt step by step and the IOCs, then confirms the Suricata
alerts on the manager.

## A hunt that cannot fail proves nothing

Two negative tests show the result is earned:

- **The hunt stays quiet on benign traffic.** Its unit tests
  ([`network/tests`](../network/tests)) run it over a capture of ordinary
  browsing and check it finds no C2. A hunt that flags everything is noise.
- **The SIEM alert depends on the rules.** Run the sensor with an empty rule
  file and Suricata loads no rules and writes zero alerts, so nothing reaches the
  manager. The detection comes from the rules, not from the traffic being there:

  ```bash
  : > tmp/empty.rules                    # tmp/ is git-ignored
  network/run-sensor.sh tmp/empty.rules  # "Suricata wrote 802 events, 0 [alerts]"
  ```

## Limits

- **Offline, not live.** The sensors read a capture file, not a live interface.
  The detections and the hunt are identical either way; a live tap is a
  deployment detail, not a logic change.
- **One hunt.** This hunts HTTP C2 beaconing. The same Zeek metadata supports
  hunts for DNS tunnelling, rare TLS fingerprints (JA3) and large outbound
  transfers (exfil); those are not built here.
- **The IOC rule is sample-specific by design.** Rule 1 names one address, to
  show what a reputation rule is and why it ages badly. Rules 2 and 3 are the
  ones that generalise.
