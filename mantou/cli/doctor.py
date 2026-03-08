"""mantou doctor command (Phase 2 tool checks only)."""

from __future__ import annotations

from pathlib import Path

import click

from mantou.cli.scan import _recount, _render_text


@click.command("doctor")
@click.option(
    "--json", "output_json", is_flag=True, default=False, help="Emit JSON output (default)"
)
@click.option("--text", "output_text", is_flag=True, default=False, help="Human-readable summary")
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
@click.option("--no-interactive", is_flag=True, default=False, envvar="MANTOU_NO_INTERACTIVE")
def doctor_cmd(
    output_json: bool,
    output_text: bool,
    workspace_path: str | None,
    config_file: str | None,
    no_interactive: bool,
) -> None:
    """Run tool-based checks only (Phase 2)."""
    import mantou.discovery as discovery
    import mantou.scanner as scanner

    context = discovery.resolve(
        config_override=Path(config_file) if config_file else None,
        workspace_override=Path(workspace_path) if workspace_path else None,
        interactive=not no_interactive,
    )

    result = scanner.run_tools_only(context)
    result = result.model_copy(update={"summary": _recount(result.findings)})

    if output_text:
        _render_text(result)
    else:
        click.echo(result.model_dump_json(indent=2))
