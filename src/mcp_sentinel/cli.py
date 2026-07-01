"""mcp-sentinel CLI.

    mcp-sentinel scan <path>            # scan an mcpServers settings.json or manifest
    mcp-sentinel rules [--category C]   # list the rule-as-data registry
    mcp-sentinel version
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from . import __version__, engine
from .engine import InputError
from .report import render
from .rules import load_rules
from .severity import Severity

app = typer.Typer(add_completion=False, help="Static security linter for the MCP trust boundary.")


def _csv(value: Optional[str]) -> Optional[list[str]]:
    if not value:
        return None
    return [x.strip() for x in value.split(",") if x.strip()]


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(f"mcp-sentinel {__version__}")


@app.command()
def rules(category: Optional[str] = typer.Option(None, "--category", "-c",
          help="filter by category: poisoning|capability|secret|supplychain|scope")) -> None:
    """List the rule registry (the same rule-as-data the engine runs)."""
    for r in load_rules():
        if category and r.category != category:
            continue
        typer.echo(f"{r.id}  [{r.severity.label:8}] {r.category:11} {r.title}")


@app.command()
def scan(
    path: str = typer.Argument(..., help="settings.json, MCP manifest, or '-' for stdin"),
    input: str = typer.Option("auto", "--input", "-i", help="auto|settings|manifest|stdio"),
    format: str = typer.Option("markdown", "--format", "-f", help="markdown|json|sarif"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="write report to FILE"),
    fail_on: str = typer.Option("medium", "--fail-on", help="exit-code threshold"),
    strict: bool = typer.Option(False, "--strict", help="any HIGH+ escalates exit code to 2"),
    offline: bool = typer.Option(False, "--offline", help="hard-disable any network/LLM path"),
    llm: bool = typer.Option(False, "--llm", help="enable optional LLM deep-check (needs API key)"),
    select: Optional[str] = typer.Option(None, "--select", help="only these rule IDs (comma-sep)"),
    ignore: Optional[str] = typer.Option(None, "--ignore", help="exclude these rule IDs (comma-sep)"),
) -> None:
    """Scan an MCP config/manifest and report security findings.

    Exit codes: 0 clean · 1 findings at/above --fail-on · 2 CRITICAL (or --strict + HIGH) · 3 error.
    """
    try:
        report = engine.scan(path, kind=input, select=_csv(select), ignore=_csv(ignore))
    except InputError as e:
        typer.secho(f"error: {e}", fg="red", err=True)
        raise typer.Exit(3)
    except Exception as e:  # unexpected — still a clean operational failure, not a crash
        typer.secho(f"error: {e}", fg="red", err=True)
        raise typer.Exit(3)

    try:
        threshold = Severity.from_str(fail_on)
    except KeyError:
        typer.secho(f"error: invalid --fail-on '{fail_on}'", fg="red", err=True)
        raise typer.Exit(3)

    rendered = render(report, format)
    if output:
        output.write_text(rendered)
        typer.echo(f"wrote {format} report to {output}")
    else:
        typer.echo(rendered)

    raise typer.Exit(report.exit_code(fail_on=threshold, strict=strict))


if __name__ == "__main__":
    app()
