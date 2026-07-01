from __future__ import annotations

import json

from mcp_sentinel import engine
from mcp_sentinel.models import Report, ScanTarget
from mcp_sentinel.report import render, render_json, render_markdown, render_sarif
from mcp_sentinel.severity import Severity


def _report(fx, name="secrets_env.json") -> Report:
    return engine.scan(fx(name))


def test_sarif_schema_valid(fx):
    doc = render_sarif(_report(fx))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcp-sentinel"
    assert len(run["results"]) == len(_report(fx).findings)
    levels = {r["level"] for r in run["results"]}
    assert levels <= {"note", "warning", "error"}
    assert any(r["level"] == "error" for r in run["results"])  # CRITICAL -> error


def test_json_schema_stable(fx):
    doc = render_json(_report(fx))
    assert doc["schema_version"] == "1.0"
    assert doc["summary"]["total"] == len(doc["findings"])
    assert sum(doc["summary"]["by_severity"].values()) == doc["summary"]["total"]
    # round-trips through json
    assert json.loads(render(_report(fx), "json"))["tool"] == "mcp-sentinel"


def test_markdown_contains_sections(fx):
    md = render_markdown(_report(fx))
    assert "mcp-sentinel report" in md
    assert "CRITICAL" in md
    assert "MCPS020" in md


def test_clean_report_markdown(fx):
    md = render_markdown(_report(fx, "clean_settings.json"))
    assert "No findings" in md


def test_severity_ordering_and_exit_codes():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO
    assert Severity.HIGH.sarif_level == "error"
    assert Severity.MEDIUM.sarif_level == "warning"
    assert Severity.LOW.sarif_level == "note"


def test_exit_code_mapping(fx):
    assert engine.scan(fx("secrets_env.json")).exit_code() == 2       # CRITICAL
    assert engine.scan(fx("unpinned_npx.json")).exit_code() == 1      # HIGH, no critical
    assert engine.scan(fx("clean_settings.json")).exit_code() == 0    # clean
    # fail-on high suppresses a medium-only report to 0
    r = Report(ScanTarget("settings", "x"), [])
    assert r.exit_code() == 0
