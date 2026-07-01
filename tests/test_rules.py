from __future__ import annotations

from mcp_sentinel.engine import load_target, run_rules
from mcp_sentinel.models import ScanTarget, ServerSpec, ToolSpec
from mcp_sentinel.rules import load_rules
from mcp_sentinel.severity import Severity


def _ids(target) -> set[str]:
    return {f.rule_id for f in run_rules(target)}


def _target_with_tool(desc="", name="t", params=None, purpose=""):
    tool = ToolSpec(name=name, description=desc, parameters=params or {})
    srv = ServerSpec(name="s", declared_purpose=purpose, tools=[tool])
    return ScanTarget(kind="settings", path="x", servers=[srv])


def test_poisoning_instruction_override(fx):
    ids = _ids(load_target(fx("poisoned_settings.json")))
    assert "MCPS001" in ids
    assert "MCPS004" in ids


def test_poisoning_invisible_unicode():
    assert "MCPS002" in _ids(_target_with_tool(desc="Search docs​hidden"))
    assert "MCPS002" not in _ids(_target_with_tool(desc="Search docs cleanly"))


def test_poisoning_base64_blob():
    blob = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5YWJj"
    assert "MCPS003" in _ids(_target_with_tool(desc=f"note {blob}"))
    assert "MCPS003" not in _ids(_target_with_tool(desc="short token abc123"))


def test_capability_shell_and_write(fx):
    ids = _ids(load_target(fx("overbroad_tool.json")))
    assert "MCPS010" in ids
    assert "MCPS011" in ids


def test_scope_capability_vs_purpose(fx):
    assert "MCPS040" in _ids(load_target(fx("overbroad_tool.json")))


def test_secret_known_key_masked(fx):
    findings = run_rules(load_target(fx("secrets_env.json")))
    s20 = [f for f in findings if f.rule_id == "MCPS020"]
    assert s20, "expected a known-format key finding"
    assert any(f.severity == Severity.CRITICAL for f in s20)
    joined = " ".join(f.location.snippet for f in s20)
    assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" not in joined  # masked
    assert "…" in joined


def test_secret_entropy_no_false_positive(fx):
    findings = run_rules(load_target(fx("secrets_env.json")))
    s21 = [f for f in findings if f.rule_id == "MCPS021"]
    assert s21  # API_SECRET high-entropy fires
    # LOG_LEVEL "info" must not be flagged anywhere
    assert all("LOG_LEVEL" not in f.location.field for f in findings if f.location.field)


def test_supplychain_unpinned_and_floating(fx):
    ids = _ids(load_target(fx("unpinned_npx.json")))
    assert "MCPS030" in ids  # some-mcp-toolbox
    assert "MCPS031" in ids  # cool-mcp@latest
    # pinned scoped package in clean config does not trip 030/031
    clean_ids = _ids(load_target(fx("clean_settings.json")))
    assert "MCPS030" not in clean_ids and "MCPS031" not in clean_ids


def test_clean_config_zero_findings(fx):
    assert run_rules(load_target(fx("clean_settings.json"))) == []


def test_load_rules_select_and_ignore():
    only = load_rules(select=["MCPS020"])
    assert [r.id for r in only] == ["MCPS020"]
    assert all(r.id != "MCPS033" for r in load_rules(ignore=["MCPS033"]))


def test_registry_completeness():
    ids = {r.id for r in load_rules()}
    for expected in ["MCPS001", "MCPS010", "MCPS020", "MCPS030", "MCPS040"]:
        assert expected in ids
    assert all(r.check is not None for r in load_rules())
