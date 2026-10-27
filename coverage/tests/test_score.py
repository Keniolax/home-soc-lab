"""Unit tests for the coverage scorer, run in CI without a lab.

They pin the classification rules and the Navigator layer shape, so a change
that would mislabel a technique or break Navigator import fails the build.
"""
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import covlib  # noqa: E402

SYSCHECK = ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/boot"]


def tech(**kw):
    base = {"id": "T9999", "fim_paths": None}
    base.update(kw)
    return base


def test_alert_means_detected():
    out = covlib.classify(tech(), [{"rule_id": "5902", "level": 8}], SYSCHECK)
    assert out["verdict"] == "detected"
    assert "5902" in out["reason"]


def test_fim_path_in_scope_means_logged():
    out = covlib.classify(
        tech(fim_paths=["/etc/profile.d/bash_completion.sh"]), [], SYSCHECK)
    assert out["verdict"] == "logged"


def test_fim_path_out_of_scope_is_blind():
    out = covlib.classify(tech(fim_paths=["/root/.ssh/authorized_keys"]), [], SYSCHECK)
    assert out["verdict"] == "blind"


def test_no_evidence_is_blind():
    assert covlib.classify(tech(), [], SYSCHECK)["verdict"] == "blind"


def test_detection_wins_over_fim():
    out = covlib.classify(
        tech(fim_paths=["/etc/x"]), [{"rule_id": "550", "level": 7}], SYSCHECK)
    assert out["verdict"] == "detected"


def test_base_id():
    assert covlib.base_id("T1087.001") == "T1087"
    assert covlib.base_id("T1110") == "T1110"


def test_substitute_fills_inputs():
    assert covlib.substitute("useradd #{username}", {"username": "bob"}) == "useradd bob"


def test_substitute_missing_arg_raises():
    with pytest.raises(KeyError):
        covlib.substitute("rm #{path}", {})


def test_apply_runid_only_named_args():
    args = covlib.apply_runid({"username": "cov", "mode": "777"}, ["username"], "123")
    assert args == {"username": "cov_123", "mode": "777"}


def test_techniques_yaml_is_well_formed():
    spec = covlib.load_spec(
        pathlib.Path(__file__).resolve().parent.parent / "techniques.yaml")
    assert spec["art_source"]["commit"]
    ids = [t["id"] for t in spec["techniques"]]
    assert len(ids) == len(set(ids)), "duplicate technique id"
    for t in spec["techniques"]:
        assert t["expect"] in covlib.VERDICTS
        assert t["tactic"]
        if not t.get("probe"):
            assert "#{" not in covlib.substitute(
                t["atomic"]["command"], t.get("args", {})), \
                f"{t['id']}: unfilled input argument"


def test_committed_layer_matches_schema_if_present():
    layer = (pathlib.Path(__file__).resolve().parent.parent
             / "navigator/coverage-layer.json")
    if not layer.exists():
        pytest.skip("no layer committed yet")
    doc = json.loads(layer.read_text())
    assert doc["domain"] == "enterprise-attack"
    assert doc["versions"]["layer"] == "4.5"
    colors = set(covlib.VERDICT_COLOR.values())
    for t in doc["techniques"]:
        assert t["techniqueID"].startswith("T")
        assert t["tactic"]
        assert t["color"] in colors, f"{t['techniqueID']}: colour off-palette"
