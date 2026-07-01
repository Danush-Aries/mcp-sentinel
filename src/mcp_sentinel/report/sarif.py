"""SARIF 2.1.0 output — drops straight into GitHub code-scanning."""
from __future__ import annotations

from .. import __version__
from ..models import Report

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def render_sarif(report: Report) -> dict:
    # One rule descriptor per rule id actually present.
    rule_index: dict[str, int] = {}
    rules: list[dict] = []
    for f in report.findings:
        if f.rule_id not in rule_index:
            rule_index[f.rule_id] = len(rules)
            rules.append({
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.remediation or f.title},
                "helpUri": f.references[0] if f.references else "",
                "properties": {"security-severity": _sec_score(f.severity)},
                "defaultConfiguration": {"level": f.severity.sarif_level},
            })

    results = []
    for f in report.findings:
        results.append({
            "ruleId": f.rule_id,
            "ruleIndex": rule_index[f.rule_id],
            "level": f.severity.sarif_level,
            "message": {"text": f.message},
            "partialFingerprints": {"mcpSentinel/v1": f.fingerprint},
            "locations": [{
                "logicalLocations": [{
                    "fullyQualifiedName": _fqn(f.location),
                    "kind": "resource",
                }],
                "physicalLocation": {
                    "artifactLocation": {"uri": report.target.path or "mcp-config"},
                },
            }],
            "properties": {
                "server": f.location.server,
                "tool": f.location.tool,
                "field": f.location.field,
            },
        })

    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "mcp-sentinel",
                "informationUri": "https://github.com/Danush-Aries/mcp-sentinel",
                "version": __version__,
                "rules": rules,
            }},
            "results": results,
        }],
    }


def _fqn(loc) -> str:
    parts = [loc.server]
    if loc.tool:
        parts.append(loc.tool)
    if loc.field:
        parts.append(loc.field)
    return "/".join(parts)


def _sec_score(sev) -> str:
    # GitHub security-severity numeric band.
    return {"info": "0.0", "low": "3.0", "medium": "5.5", "high": "7.5", "critical": "9.5"}[sev.label]
