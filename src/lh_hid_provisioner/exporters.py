"""Report exporters for Table, JSON, and SARIF v2.1.0 formats."""

import json
from io import StringIO
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from lh_hid_provisioner import __version__
from lh_hid_provisioner.models import LintReport, Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "blue",
}


def export_table(report: LintReport, console: Console | None = None) -> str:
    """Format lint report as a Rich terminal table.

    Args:
        report: LintReport to display.
        console: Optional existing Rich console.

    Returns:
        Rendered string representation.
    """
    string_buffer = StringIO()
    render_console = console or Console(file=string_buffer, force_terminal=True, width=120)

    if not report.findings:
        render_console.print(
            Panel(
                "[bold green]✓ No issues found. HID script passed all checks![/bold green]",
                title="[bold green]Logihertz HID Linter - PASS[/bold green]",
                border_style="green",
            )
        )
        return string_buffer.getvalue()

    table = Table(
        title=f"Logihertz HID Linter Findings: {report.file_path}",
        header_style="bold magenta",
        border_style="dim",
        expand=True,
    )

    table.add_column("Line", justify="right", style="cyan", no_wrap=True)
    table.add_column("Rule ID", style="bold", no_wrap=True)
    table.add_column("Severity", justify="center", no_wrap=True)
    table.add_column("Finding / Message", style="white")
    table.add_column("Snippet & Suggestion", style="dim")

    for f in report.findings:
        sev_color = SEVERITY_COLORS.get(f.severity, "white")
        snippet_display = f"[bold]{f.code_snippet}[/bold]"
        if f.suggestion:
            snippet_display += f"\n[italic cyan]↳ {f.suggestion}[/italic cyan]"

        table.add_row(
            str(f.line_number),
            f.rule_id,
            f"[{sev_color}]{f.severity.value.upper()}[/{sev_color}]",
            f.message,
            snippet_display,
        )

    render_console.print(table)

    summary_text = (
        f"[bold]Total Issues:[/bold] {report.total_issues} | "
        f"[bold red]Critical:[/bold red] {report.critical_count} | "
        f"[red]High:[/red] {report.high_count} | "
        f"[yellow]Medium:[/yellow] {report.medium_count} | "
        f"[cyan]Low:[/cyan] {report.low_count}"
    )
    border_color = "red" if report.critical_count > 0 or report.high_count > 0 else "yellow"
    render_console.print(
        Panel(summary_text, title="[bold]Summary[/bold]", border_style=border_color)
    )

    return string_buffer.getvalue()


def export_json(report: LintReport) -> str:
    """Format lint report as structured JSON.

    Args:
        report: LintReport to serialize.

    Returns:
        JSON string representation.
    """
    data: dict[str, Any] = {
        "file": report.file_path,
        "passed": not report.has_failures(strict=False),
        "summary": {
            "total_issues": report.total_issues,
            "critical": report.critical_count,
            "high": report.high_count,
            "medium": report.medium_count,
            "low": report.low_count,
            "info": report.info_count,
        },
        "findings": [
            {
                "line": f.line_number,
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "severity": f.severity.value,
                "message": f.message,
                "code_snippet": f.code_snippet,
                "suggestion": f.suggestion,
            }
            for f in report.findings
        ],
    }
    return json.dumps(data, indent=2)


def export_sarif(report: LintReport) -> str:
    """Format lint report as OASIS SARIF v2.1.0 JSON format.

    Args:
        report: LintReport to serialize.

    Returns:
        SARIF v2.1.0 compliant JSON string.
    """
    # Extract unique rules from report findings
    rules_dict: dict[str, dict[str, Any]] = {}
    for f in report.findings:
        if f.rule_id not in rules_dict:
            rules_dict[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_name,
                "shortDescription": {"text": f.rule_name},
                "defaultConfiguration": {"level": f.severity.sarif_level},
            }

    results: list[dict[str, Any]] = []
    for f in report.findings:
        results.append(
            {
                "ruleId": f.rule_id,
                "level": f.severity.sarif_level,
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": report.file_path},
                            "region": {
                                "startLine": f.line_number,
                                "snippet": {"text": f.code_snippet},
                            },
                        }
                    }
                ],
            }
        )

    sarif_data: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "lh-hid-provisioner",
                        "version": __version__,
                        "informationUri": "https://github.com/logihertz/lh-hid-provisioner",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif_data, indent=2)
