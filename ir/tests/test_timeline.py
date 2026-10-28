"""Unit tests for the IR timeline builder.

Like the hunt tests, these run over the small Zeek log fixtures and need no lab.
CI runs them.
"""
import pathlib
import sys

IR = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(IR))
import timeline as T  # noqa: E402

FIX = IR.parent / "network/tests/fixtures"


def load(kind):
    import hunt_lib as H
    d = FIX / kind
    return (H.read_zeek(d / "conn.log"),
            H.read_zeek(d / "http.log"),
            H.read_zeek(d / "dns.log"))


def test_timeline_finds_the_incident():
    r = T.build_timeline(*load("malicious"), alert_ts=[])
    assert r["finding"] is not None
    f = r["facts"]
    assert f["infected_host"] == "172.17.0.99"
    assert f["c2_server"] == "79.124.78.197"
    assert f["c2_connections"] >= 14
    assert "T1071.001" in f["mitre"]


def test_timeline_is_chronological():
    r = T.build_timeline(*load("malicious"), alert_ts=[])
    epochs = [e["epoch"] for e in r["events"]]
    assert epochs == sorted(epochs)
    # First event is the capture start; last is the capture end.
    assert "Capture begins" in r["events"][0]["event"]
    assert "Capture ends" in r["events"][-1]["event"]


def test_every_event_cites_a_source():
    r = T.build_timeline(*load("malicious"), alert_ts=[])
    assert all(e["source"] for e in r["events"])


def test_no_incident_no_timeline():
    r = T.build_timeline(*load("benign"), alert_ts=[])
    assert r["finding"] is None
    assert r["events"] == []
