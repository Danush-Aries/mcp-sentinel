"""The scan engine: load a target, run every rule, assemble a sorted Report.

This is the only place parsers, rules, and models meet. Imports of sibling
modules are deferred so the package stays importable during parallel builds.
"""
from __future__ import annotations

from .models import Finding, Report, ScanTarget


class InputError(Exception):
    """Raised for unreadable/unparseable input — maps to CLI exit code 3."""


def load_target(path: str, kind: str = "auto") -> ScanTarget:
    """Dispatch to the parsers package. Kept here as the public entry point."""
    from .parsers import load_target as _load
    return _load(path, kind)


def run_rules(target: ScanTarget, select: list[str] | None = None,
              ignore: list[str] | None = None) -> list[Finding]:
    from .rules import load_rules
    findings: list[Finding] = []
    for rule in load_rules(select=select, ignore=ignore):
        if rule.check is None:
            continue
        for f in rule.check(target):
            findings.append(f.with_fingerprint())
    return _sorted(findings)


def scan(path: str, kind: str = "auto", select: list[str] | None = None,
         ignore: list[str] | None = None) -> Report:
    """Full pipeline: parse → run rules → Report."""
    target = load_target(path, kind)
    findings = run_rules(target, select=select, ignore=ignore)
    return Report(target=target, findings=findings)


def _sorted(findings: list[Finding]) -> list[Finding]:
    # Highest severity first, then rule id, then server for stable output.
    return sorted(
        findings,
        key=lambda f: (-int(f.severity), f.rule_id, f.location.server, f.location.tool or ""),
    )
