"""Pure helpers for the network threat hunt.

The only I/O is reading Zeek TSV logs; every judgement (what counts as external,
which destination beacons, which Host header is a raw IP) is a plain function, so
the hunt's logic is unit-tested without a live lab.
"""
from __future__ import annotations

import ipaddress
import pathlib
import statistics

# RFC 1918 private ranges. The capture's network is 172.17.0.0/16, inside
# 172.16.0.0/12; anything outside these three ranges is "external" (the
# internet), where a C2 server lives.
HOME_NETS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")


def is_external(ip: str, home_nets: tuple[str, ...] = HOME_NETS) -> bool:
    """True if ip is a routable address outside the home network."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_multicast or addr.is_loopback or addr.is_unspecified:
        return False
    return not any(addr in ipaddress.ip_network(n) for n in home_nets)


def is_ipv4_literal(host: str) -> bool:
    """True if a HTTP Host header is a bare IPv4 address, not a domain name."""
    try:
        return isinstance(ipaddress.ip_address(host), ipaddress.IPv4Address)
    except ValueError:
        return False


def read_zeek(path: str | pathlib.Path) -> list[dict]:
    """Parse a Zeek TSV log into a list of dict rows keyed by field name.

    Zeek writes the column names in a '#fields' header and marks an absent value
    with '#unset_field' (default '-') and an empty string with '#empty_field'
    (default '(empty)'). Both become '' here.
    """
    path = pathlib.Path(path)
    if not path.exists():
        return []
    fields: list[str] = []
    unset, empty = "-", "(empty)"
    rows: list[dict] = []
    for line in path.read_text().splitlines():
        if line.startswith("#"):
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line.startswith("#unset_field"):
                unset = line.split("\t", 1)[1]
            elif line.startswith("#empty_field"):
                empty = line.split("\t", 1)[1]
            continue
        if not fields:
            continue
        values = line.split("\t")
        row = {}
        for name, value in zip(fields, values):
            row[name] = "" if value in (unset, empty) else value
        rows.append(row)
    return rows


def dns_resolved_ips(dns_rows: list[dict]) -> set[str]:
    """Every IP address that appears as a DNS answer in the capture.

    A destination reached without ever appearing here was contacted by raw IP,
    with no name lookup -- a hallmark of malware that hardcodes its C2 address.
    """
    ips: set[str] = set()
    for row in dns_rows:
        for answer in (row.get("answers") or "").split(","):
            answer = answer.strip()
            try:
                ipaddress.ip_address(answer)
                ips.add(answer)
            except ValueError:
                pass  # a CNAME or other non-address answer
    return ips


def beacon_table(conn_rows: list[dict],
                 home_nets: tuple[str, ...] = HOME_NETS) -> list[dict]:
    """One row per internal-host -> external-host pair, ranked by connections.

    For each pair it records how many connections there were, the bytes sent,
    and the timing of the connection starts: a host that beacons calls the same
    destination many times, so the pair with by far the most connections is the
    first thing a hunt looks at.
    """
    pairs: dict[tuple[str, str], dict] = {}
    for row in conn_rows:
        src, dst = row.get("id.orig_h", ""), row.get("id.resp_h", "")
        if not is_external(dst, home_nets):
            continue
        key = (src, dst)
        p = pairs.setdefault(key, {"orig": src, "resp": dst, "conns": 0,
                                   "orig_bytes": 0, "_ts": []})
        p["conns"] += 1
        p["orig_bytes"] += _int(row.get("orig_bytes"))
        ts = _float(row.get("ts"))
        if ts is not None:
            p["_ts"].append(ts)

    table = []
    for p in pairs.values():
        ts = sorted(p.pop("_ts"))
        p["span_s"] = round(ts[-1] - ts[0], 1) if len(ts) > 1 else 0.0
        p["interval_mean_s"] = _mean_interval(ts)
        table.append(p)
    table.sort(key=lambda r: r["conns"], reverse=True)
    return table


def http_sessions_to(http_rows: list[dict], dst: str) -> list[dict]:
    """The HTTP requests sent to one destination address."""
    return [r for r in http_rows if r.get("id.resp_h") == dst]


def tally(rows: list[dict], field: str) -> list[tuple[str, int]]:
    """Count distinct values of a field, most common first."""
    counts: dict[str, int] = {}
    for r in rows:
        counts[r.get(field, "")] = counts.get(r.get(field, ""), 0) + 1
    return sorted(counts.items(), key=lambda kv: kv[1], reverse=True)


def classify_c2(conn_rows: list[dict], http_rows: list[dict], dns_rows: list[dict],
                min_http_requests: int = 10,
                home_nets: tuple[str, ...] = HOME_NETS) -> dict:
    """Run the hunt's logic and return its working and its findings.

    A destination is called a C2 server when an internal host sends it at least
    `min_http_requests` HTTP requests, reaches it by a raw IP with no DNS lookup,
    and POSTs to it. The caller prints the working (the beacon table and the two
    follow-up queries) and turns a finding into IOCs.
    """
    beacons = beacon_table(conn_rows, home_nets)
    out = {"beacons": beacons, "top": None, "query2": None, "query3": None,
           "findings": []}
    if not beacons:
        return out
    top = beacons[0]
    out["top"] = top

    resolved = dns_resolved_ips(dns_rows)
    http_to_top = http_sessions_to(http_rows, top["resp"])
    hosts = {r.get("host", "") for r in http_to_top}
    raw_ip = any(is_ipv4_literal(h) for h in hosts)
    via_dns = top["resp"] in resolved
    out["query2"] = {"hosts": sorted(hosts), "raw_ip": raw_ip, "via_dns": via_dns}

    methods = tally(http_to_top, "method")
    uris = tally(http_to_top, "uri")
    uas = tally(http_to_top, "user_agent")
    out["query3"] = {"methods": methods, "uris": uris, "uas": uas,
                     "http_count": len(http_to_top)}

    if (len(http_to_top) >= min_http_requests and raw_ip and not via_dns
            and any(m == "POST" for m, _ in methods)):
        out["findings"].append({
            "infected_host": top["orig"],
            "c2_server": top["resp"],
            "c2_port": _dominant_resp_port(conn_rows, top["resp"]),
            "protocol": "HTTP",
            "http_requests": len(http_to_top),
            "beacon_span_s": top["span_s"],
            "beacon_mean_interval_s": top["interval_mean_s"],
            "c2_uris": [u for u, _ in uris if u],
            "malware_user_agent": next((u for u, _ in uas if u), ""),
            "addressed_by_raw_ip": raw_ip,
            "resolved_by_dns": via_dns,
            "mitre": "T1071.001",
        })
    return out


def _dominant_resp_port(conn_rows: list[dict], dst: str) -> str:
    ports = tally([r for r in conn_rows if r.get("id.resp_h") == dst], "id.resp_p")
    return ports[0][0] if ports else ""


def _mean_interval(sorted_ts: list[float]) -> float:
    if len(sorted_ts) < 2:
        return 0.0
    gaps = [b - a for a, b in zip(sorted_ts, sorted_ts[1:])]
    return round(statistics.mean(gaps), 1)


def _int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
