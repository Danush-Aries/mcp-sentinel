"""Report rendering dispatch: markdown | json | sarif."""
from __future__ import annotations

import json

from ..models import Report
from .json_out import render_json
from .markdown import render_markdown
from .sarif import render_sarif

__all__ = ["render", "render_markdown", "render_json", "render_sarif"]


def render(report: Report, fmt: str = "markdown") -> str:
    fmt = fmt.lower()
    if fmt == "markdown":
        return render_markdown(report)
    if fmt == "json":
        return json.dumps(render_json(report), indent=2)
    if fmt == "sarif":
        return json.dumps(render_sarif(report), indent=2)
    raise ValueError(f"unknown report format: {fmt}")
