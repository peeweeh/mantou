"""Mantou CLI entry point."""

import click

from mantou import __version__
from mantou.cli.rules import rules_cmd
from mantou.cli.scan import scan_cmd


@click.group()
@click.version_option(__version__, prog_name="mantou")
def cli() -> None:
    """Mantou — OpenClaw security posture scanner."""


cli.add_command(scan_cmd, name="scan")
cli.add_command(rules_cmd, name="rules")
