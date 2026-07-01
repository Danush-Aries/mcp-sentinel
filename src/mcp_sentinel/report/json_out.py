"""Stable machine-readable JSON output."""
from __future__ import annotations

from ..models import Finding, Report


def _finding_dict(f: Finding) -> dict:
    return {
        "rule_id": f.rule_id,
        "title": f.title,
        "severity": f.severity.label,
        "message": f.message,
        "location": {
            "server": f.location.server,
            "tool": f.location.tool,
            "field": f.location.field,
            "snippet": f.location.snippet,
        },
        "remediation": f.remediation,
        "references": list(f.references),
        "fingerprint": f.fingerprint,
    }


def render_json(report: Report) -> dict:
    return {
        "schema_version": report.schema_version,
        "tool": "mcp-sentinel",
        "tool_version": report.tool_version,
        "target": {"kind": report.target.kind, "path": report.target.path,
                   "servers": [s.name for s in report.target.servers]},
        "summary": {
            "total": len(report.findings),
            "by_severity": report.counts_by_severity,
            "highest_severity": report.highest_severity.label if report.highest_severity else None,
        },
        "findings": [_finding_dict(f) for f in report.findings],
    }
