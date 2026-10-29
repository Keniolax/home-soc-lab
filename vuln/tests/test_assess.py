"""Tests for the week-8 closure proof (vuln/assess.py).

These run in CI without a lab, a scanner or a network. They scan nothing; they
feed assess.py small before/after Trivy reports and check that it proves closure
only when the remediated findings really went away and the deferred one stayed.
A change that lets assess.py pass on an image that was never patched — the one
failure that would make the whole week a lie — fails here.
"""
import importlib.util
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
FIX = HERE / "fixtures"

# Load assess.py (a script next to this test's parent) as a module.
spec = importlib.util.spec_from_file_location("assess", HERE.parent / "assess.py")
assess = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assess)


def test_before_fixture_has_the_representative_findings():
    before = assess.load(FIX / "before.json")
    for cve in ("CVE-2024-6119", "CVE-2024-2961", "CVE-2024-10963", "CVE-2025-68973"):
        assert assess.present(before, cve), f"{cve} should be in the before scan"


def test_closure_proven_when_fixes_land():
    before = assess.load(FIX / "before.json")
    after = assess.load(FIX / "after.json")
    summary, failures = assess.evaluate(before, after)
    assert failures == []
    assert summary["proven"] is True
    by_id = {f["id"]: f for f in summary["remediated"]}
    assert set(by_id) == {"openssl", "glibc", "pam"}
    for finding in by_id.values():
        assert finding["status"] == "closed"
        assert finding["representative_cve"] in finding["cves_closed"]
    # The deferred finding is still there, so the re-scan reflects the image.
    assert summary["deferred"]["still_present_after"] is True


def test_not_proven_when_nothing_was_patched():
    # after == before: the fixes never landed, so the proof must fail.
    before = assess.load(FIX / "before.json")
    summary, failures = assess.evaluate(before, before)
    assert summary["proven"] is False
    assert len(failures) == 3
    for finding in summary["remediated"]:
        assert finding["status"] == "NOT CLOSED"


def test_not_proven_when_deferred_finding_vanishes():
    # If the deferred finding disappears too, the after-scan no longer matches
    # the image we claim to have shipped; refuse to call it proven.
    before = assess.load(FIX / "before.json")
    after = assess.load(FIX / "after.json")
    after = {k: v for k, v in after.items() if k[0] != "CVE-2025-68973"}
    summary, failures = assess.evaluate(before, after)
    assert summary["proven"] is False
    assert any("gpgv" in f for f in failures)


def test_committed_summary_matches_the_model():
    # The evidence committed from the real run must say the week is proven.
    summary = json.loads((HERE.parent.parent / "docs/evidence/vuln/summary.json").read_text())
    assert summary["proven"] is True
    assert {f["id"] for f in summary["remediated"]} == {"openssl", "glibc", "pam"}
    assert summary["deferred"]["still_present_after"] is True
    assert summary["after"]["total"] < summary["before"]["total"]
