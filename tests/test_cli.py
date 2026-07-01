from __future__ import annotations

import json

from typer.testing import CliRunner

from mcp_sentinel.cli import app

runner = CliRunner()


def test_version():
    r = runner.invoke(app, ["version"])
    assert r.exit_code == 0
    assert "mcp-sentinel" in r.stdout


def test_rules_listing():
    r = runner.invoke(app, ["rules"])
    assert r.exit_code == 0
    assert "MCPS001" in r.stdout
    assert "MCPS020" in r.stdout


def test_scan_clean_exit_zero(fx):
    r = runner.invoke(app, ["scan", fx("clean_settings.json")])
    assert r.exit_code == 0
    assert "No findings" in r.stdout


def test_scan_critical_exit_two(fx):
    r = runner.invoke(app, ["scan", fx("secrets_env.json")])
    assert r.exit_code == 2


def test_scan_high_exit_one(fx):
    r = runner.invoke(app, ["scan", fx("unpinned_npx.json")])
    assert r.exit_code == 1


def test_scan_bad_input_exit_three(fx):
    r = runner.invoke(app, ["scan", fx("malformed.json")])
    assert r.exit_code == 3


def test_scan_json_format(fx):
    r = runner.invoke(app, ["scan", fx("poisoned_settings.json"), "--format", "json"])
    # exit 1 (findings) but stdout is valid JSON
    payload = json.loads(r.stdout)
    assert payload["tool"] == "mcp-sentinel"
    assert payload["summary"]["total"] >= 1


def test_scan_sarif_format(fx):
    r = runner.invoke(app, ["scan", fx("secrets_env.json"), "--format", "sarif"])
    doc = json.loads(r.stdout)
    assert doc["version"] == "2.1.0"


def test_scan_select_narrows(fx):
    r = runner.invoke(app, ["scan", fx("unpinned_npx.json"), "--select", "MCPS030", "--format", "json"])
    payload = json.loads(r.stdout)
    assert {f["rule_id"] for f in payload["findings"]} == {"MCPS030"}
