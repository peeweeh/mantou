"""mantou scan command."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click

from mantou.schema import SEVERITY_ORDER, ScanResult, ScanSummary


@click.command("scan")
@click.option(
    "--json", "output_json", is_flag=True, default=False, help="Emit JSON output (default)"
)
@click.option("--text", "output_text", is_flag=True, default=False, help="Human-readable summary")
@click.option(
    "--min-severity",
    default="low",
    type=click.Choice(["info", "low", "medium", "high", "critical"]),
    help="Filter findings below this level.",
)
@click.option(
    "--exit-on",
    default=None,
    type=click.Choice(["info", "low", "medium", "high", "critical"]),
    help="Exit 1 if any findings at/above this level.",
)
@click.option(
    "--path",
    "workspace_path",
    default=None,
    type=click.Path(),
    help="Workspace directory override.",
)
@click.option(
    "--config", "config_file", default=None, type=click.Path(), help="Path to openclaw.json."
)
@click.option(
    "--rules", "rules_dir", default=None, type=click.Path(), help="Rules directory override."
)
@click.option("--no-os-probes", is_flag=True, default=False, help="Skip command-based probes.")
@click.option(
    "--include-info", is_flag=True, default=False, help="Include info-severity in output."
)
@click.option(
    "--root", default=None, type=click.Path(), help="Re-root all path resolution (VM scan mode)."
)
@click.option("--vm-user", default=None, help="Username override for VM scan mode.")
@click.option(
    "--allow-os-probes", is_flag=True, default=False, help="Allow OS probes when --root is set."
)
@click.option("--skip-tools", is_flag=True, default=False, help="Skip Phase 2 tool invocations.")
@click.option("--no-interactive", is_flag=True, default=False, envvar="MANTOU_NO_INTERACTIVE")
def scan_cmd(
    output_json: bool,
    output_text: bool,
    min_severity: str,
    exit_on: str | None,
    workspace_path: str | None,
    config_file: str | None,
    rules_dir: str | None,
    no_os_probes: bool,
    include_info: bool,
    root: str | None,
    vm_user: str | None,
    allow_os_probes: bool,
    skip_tools: bool,
    no_interactive: bool,
) -> None:
    """Scan OpenClaw configuration and emit security findings."""
    import mantou.discovery as discovery
    import mantou.scanner as scanner
    from mantou.scanner import ScanOptions

    context = discovery.resolve(
        config_override=Path(config_file) if config_file else None,
        workspace_override=Path(workspace_path) if workspace_path else None,
        root_override=Path(root) if root else None,
        vm_user=vm_user,
        allow_os_probes=allow_os_probes,
        interactive=not no_interactive,
    )

    options = ScanOptions(
        min_severity=min_severity,
        exit_on=exit_on,
        no_os_probes=no_os_probes,
        include_info=include_info,
        rules_dir=Path(rules_dir) if rules_dir else scanner._RULES_DIR,
    )

    if skip_tools:
        os.environ["MANTOU_SKIP_TOOLS"] = "1"
    result = scanner.run(context, options)

    # Filter findings
    min_level = SEVERITY_ORDER.get(min_severity, 0)
    filtered = [
        f
        for f in result.findings
        if SEVERITY_ORDER.get(f.severity, 0) >= min_level or (include_info and f.severity == "info")
    ]
    result = result.model_copy(update={"findings": filtered, "summary": _recount(filtered)})

    if output_text:
        _render_text(result)
    else:
        click.echo(result.model_dump_json(indent=2))

    # Exit code logic
    if exit_on:
        threshold = SEVERITY_ORDER.get(exit_on, 0)
        if any(SEVERITY_ORDER.get(f.severity, 0) >= threshold for f in filtered):
            sys.exit(1)
    sys.exit(0)


def _recount(findings: list) -> ScanSummary:
    from mantou.schema import build_summary

    return build_summary(findings)


def _render_text(result: ScanResult) -> None:
    click.echo(f"\nMantou {result.mantou_version} — OpenClaw Security Posture Scan")
    click.echo(
        f"Scanned: {result.timestamp}  |  Duration: {result.duration_ms}ms  "
        f"|  Platform: {result.platform.os}"
    )
    click.echo(f"OpenClaw status: {result.openclaw.status}")
    click.echo("")

    s = result.summary
    click.echo(
        f"Findings: {s.total} total  "
        f"({s.critical} critical, {s.high} high, {s.medium} medium, "
        f"{s.low} low, {s.info} info)"
    )
    click.echo("")

    _SEVERITY_ICON = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
    }

    if not result.findings:
        click.echo("  No findings above threshold.")
    else:
        for f in sorted(result.findings, key=lambda x: -SEVERITY_ORDER.get(x.severity, 0)):
            icon = _SEVERITY_ICON.get(f.severity, "•")
            click.echo(f"  {icon} [{f.id}] {f.title}")
            click.echo(f"     {f.detail}")
            click.echo(f"     Resource: {f.resource}")
            if f.evidence:
                click.echo(f"     Evidence: {f.evidence}")
            click.echo(f"     Fix: {f.remediation}")
            click.echo("")

    if result.partial_failures:
        click.echo(f"Partial failures ({len(result.partial_failures)}):")
        for pf in result.partial_failures:
            click.echo(f"  ⚠ [{pf.rule_id}] {pf.reason}: {pf.detail}")
        click.echo("")
