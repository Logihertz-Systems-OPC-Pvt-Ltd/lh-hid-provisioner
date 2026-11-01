# ==============================================================================
# Product:       lh-hid-provisioner (lh-provision)
# Module:        src.lh_hid_provisioner.cli
# Role:          CLI Interface & Execution Controller
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Command-line interface (CLI) for lh-hid-provisioner."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from lh_hid_provisioner import __version__
from lh_hid_provisioner.compiler import compile_profile
from lh_hid_provisioner.exporters import export_json, export_sarif, export_table
from lh_hid_provisioner.linter import lint_script
from lh_hid_provisioner.models import OutputFormat, TargetOS
from lh_hid_provisioner.parser import ProfileValidationError, parse_profile
from lh_hid_provisioner.templates import generate_template

# --- Exit Code Semantics ---
# Exit Code 0: Audit passed successfully with zero policy violations.
# Exit Code 1: Security findings detected meeting or exceeding failure threshold (--fail-on).
# Exit Code 2: Command execution error, invalid arguments, or unparseable input target.

app = typer.Typer(
    name="lh-provision",
    help=(
        "Clean-room CLI tool by Logihertz Systems OPC Pvt Ltd to compile declarative "
        "YAML server profiles into USB HID automation scripts and lint existing scripts."
    ),
    add_completion=False,
    no_args_is_help=True,
)

err_console = Console(stderr=True)
stdout_console = Console()


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        stdout_console.print(f"lh-provision v{__version__} (Logihertz Systems OPC Pvt Ltd)")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-v",
            help="Show version and exit.",
            callback=version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """Entrypoint callback."""


@app.command(name="compile", help="Compile a declarative YAML profile into an HID script.")
def compile_cmd(
    profile_path: Annotated[
        Path,
        typer.Argument(
            metavar="<profile.yaml>",
            help="Path to declarative YAML profile file.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ],
    target_os: Annotated[
        TargetOS,
        typer.Option(
            "--target-os",
            "-t",
            case_sensitive=False,
            help="Target operating system: debian, ubuntu, or alpine.",
        ),
    ],
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Output destination path for the compiled script (default: stdout).",
        ),
    ] = None,
) -> None:
    """Compile YAML server profile into deterministic HID keystroke automation script."""
    try:
        profile = parse_profile(profile_path)
    except (ProfileValidationError, FileNotFoundError, OSError) as err:
        err_console.print(f"[bold red]Profile Error:[/bold red] {err}")
        raise typer.Exit(code=1) from err

    compiled_script = compile_profile(profile, target_os)

    if output is not None:
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(compiled_script, encoding="utf-8")
            stdout_console.print(
                f"[bold green]✓[/bold green] Compiled HID script written to [cyan]{output}[/cyan]"
            )
        except OSError as err:
            err_console.print(
                f"[bold red]Output Error:[/bold red] Failed to write to {output}: {err}"
            )
            raise typer.Exit(code=1) from err
    else:
        typer.echo(compiled_script, nl=False)


@app.command(
    name="lint",
    help="Lint an HID keystroke script for syntax errors and security guardrails.",
)
def lint_cmd(
    script_path: Annotated[
        Path,
        typer.Argument(
            metavar="<script.txt>",
            help="Path to HID keystroke script file.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ],
    strict: Annotated[
        bool,
        typer.Option(
            "--strict",
            help="Strict mode: fail on all findings including warnings.",
        ),
    ] = False,
    format_opt: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            case_sensitive=False,
            help="Output report format: table, json, or sarif.",
        ),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Output destination path for the lint report (default: stdout).",
        ),
    ] = None,
) -> None:
    """Lint HID automation script for invalid commands, delays, and security guardrails."""
    try:
        report = lint_script(script_path)
    except OSError as err:
        err_console.print(f"[bold red]Read Error:[/bold red] Could not read '{script_path}': {err}")
        raise typer.Exit(code=1) from err

    match format_opt:
        case OutputFormat.TABLE:
            formatted = export_table(report)
        case OutputFormat.JSON:
            formatted = export_json(report)
        case OutputFormat.SARIF:
            formatted = export_sarif(report)

    if output is not None:
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(formatted, encoding="utf-8")
        except OSError as err:
            err_console.print(
                f"[bold red]Output Error:[/bold red] Failed to write report to {output}: {err}"
            )
            raise typer.Exit(code=1) from err
    else:
        typer.echo(formatted, nl=False)

    if report.has_failures(strict=strict):
        raise typer.Exit(code=1)


@app.command(name="init-template", help="Generate a declarative YAML profile template.")
def init_template_cmd(
    target_os: Annotated[
        TargetOS,
        typer.Option(
            "--target-os",
            "-t",
            case_sensitive=False,
            help="Target operating system: debian, ubuntu, or alpine.",
        ),
    ] = TargetOS.DEBIAN,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Output destination path for YAML template (default: stdout).",
        ),
    ] = None,
) -> None:
    """Generate a starter declarative YAML server provisioning profile template."""
    template_content = generate_template(target_os)

    if output is not None:
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(template_content, encoding="utf-8")
            stdout_console.print(
                f"[bold green]✓[/bold green] Profile template for [bold]{target_os.value}[/bold] "
                f"written to [cyan]{output}[/cyan]"
            )
        except OSError as err:
            err_console.print(
                f"[bold red]Output Error:[/bold red] Failed to write template to {output}: {err}"
            )
            raise typer.Exit(code=1) from err
    else:
        typer.echo(template_content, nl=False)
