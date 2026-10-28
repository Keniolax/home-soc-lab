# AI first draft of the incident timeline — UNVERIFIED

This is a timeline of the incident as a large language model drafted it from a
short description ("a Windows host was beaconing to an HTTP C2 server; here are
the IOCs"), **before** checking any of it against the capture. It is kept to show
what the model asserted and how much of it the evidence actually supports. Do not
cite it. The checked version is in [`../docs/ir-report.md`](../docs/ir-report.md).

---

An employee at bepositive.com received a phishing email with a malicious Office
attachment. On opening it, a macro downloaded and ran the Amadey loader, which
exploited CVE-2023-21674 to gain SYSTEM privileges on DESKTOP-RNVO9AT
(172.17.0.99).

The loader first sent a registration request to its command-and-control server
at 79.124.78.197, then began checking in every 60 seconds with POST requests to
`/foots.php`. Over roughly 57 minutes it exfiltrated harvested credentials and
browser data to the C2.

The attacker then moved laterally across the network over SMB, compromising
additional hosts in the bepositive.com domain, and used the stolen domain
credentials to authenticate to internal servers.

The total dwell time was about 57 minutes, from initial compromise to the end of
the captured activity. The malware was identified as Amadey based on its C2 URI
pattern and User-Agent.
