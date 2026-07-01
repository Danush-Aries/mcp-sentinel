"""Human-readable Markdown report, grouped by severity."""
from __future__ import annotations

from ..models import Report
from ..severity import Severity

_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def render_markdown(report: Report) -> str:
    lines: list[str] = []
    lines.append(f"# mcp-sentinel report — `{report.target.path or 'mcp-config'}`\n")
    counts = report.counts_by_severity
    if not report.findings:
        lines.append("✅ **No findings.** No poisoning, capability, secret, or supply-chain "
                     "issues detected in the MCP trust boundary.\n")
        return "\n".join(lines)

    summary = "  ".join(f"{_ICON[s]} {counts[s]} {s}" for s in
                        ["critical", "high", "medium", "low", "info"] if counts.get(s))
    lines.append(f"**{len(report.findings)} findings** — {summary}\n")

    by_sev = {s: [f for f in report.findings if f.severity == s] for s in _ORDER}
    for sev in _ORDER:
        group = by_sev[sev]
        if not group:
            continue
        lines.append(f"## {_ICON[sev.label]} {sev.label.upper()}\n")
        for f in group:
            loc = f.location
            where = loc.server + (f" › {loc.tool}" if loc.tool else "") + (f" › {loc.field}" if loc.field else "")
            lines.append(f"### `{f.rule_id}` {f.title}")
            lines.append(f"- **Where:** {where}")
            lines.append(f"- **Detail:** {f.message}")
            if loc.snippet:
                lines.append(f"- **Evidence:** `{loc.snippet}`")
            if f.remediation:
                lines.append(f"- **Fix:** {f.remediation}")
            lines.append("")
    return "\n".join(lines)
