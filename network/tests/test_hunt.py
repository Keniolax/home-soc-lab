"""Unit tests for the threat-hunt logic.

These need no lab: they run the hunt's functions over small Zeek log fixtures,
one with C2 beaconing and one with only benign browsing, and check that the hunt
finds the C2 in the first and nothing in the second. CI runs these.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import hunt_lib as H  # noqa: E402

FIX = pathlib.Path(__file__).resolve().parent / "fixtures"


def load(kind):
    d = FIX / kind
    return (H.read_zeek(d / "conn.log"),
            H.read_zeek(d / "http.log"),
            H.read_zeek(d / "dns.log"))


def test_is_external():
    assert H.is_external("79.124.78.197")
    assert not H.is_external("172.17.0.99")   # 172.16/12
    assert not H.is_external("192.168.1.50")
    assert not H.is_external("10.1.2.3")
    assert not H.is_external("127.0.0.1")
    assert not H.is_external("not-an-ip")


def test_is_ipv4_literal():
    assert H.is_ipv4_literal("79.124.78.197")
    assert not H.is_ipv4_literal("www.bing.com")
    assert not H.is_ipv4_literal("")


def test_read_zeek_parses_fields_and_blanks():
    http, = (H.read_zeek(FIX / "malicious/http.log"),)
    assert http[0]["id.resp_h"] == "79.124.78.197"
    assert http[0]["method"] == "POST"
    assert http[0]["uri"] == "/foots.php"


def test_dns_resolved_ips():
    _, _, dns = load("malicious")
    ips = H.dns_resolved_ips(dns)
    assert "23.45.119.144" in ips
    assert "79.124.78.197" not in ips   # the C2 was never resolved by name


def test_beacon_table_ranks_c2_first():
    conn, _, _ = load("malicious")
    table = H.beacon_table(conn)
    assert table[0]["resp"] == "79.124.78.197"
    assert table[0]["conns"] >= 14


def test_classify_finds_c2_in_malicious():
    findings = H.classify_c2(*load("malicious"))["findings"]
    assert len(findings) == 1
    f = findings[0]
    assert f["infected_host"] == "172.17.0.99"
    assert f["c2_server"] == "79.124.78.197"
    assert f["c2_port"] == "80"
    assert "/foots.php" in f["c2_uris"]
    assert "MSIE 7.0" in f["malware_user_agent"]
    assert f["addressed_by_raw_ip"] and not f["resolved_by_dns"]
    assert f["mitre"] == "T1071.001"


def test_classify_finds_nothing_in_benign():
    # The hunt must stay quiet on ordinary browsing, or it is just noise.
    assert H.classify_c2(*load("benign"))["findings"] == []


def test_classify_needs_raw_ip_not_just_volume():
    # Same beacon volume, but reached by a resolved domain -> not flagged.
    conn, http, dns = load("malicious")
    for row in http:
        row["host"] = "cdn.example.com"      # now addressed by name
    dns = dns + [{"answers": "79.124.78.197"}]  # and resolved by DNS
    assert H.classify_c2(conn, http, dns)["findings"] == []
