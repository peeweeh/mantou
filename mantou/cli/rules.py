"""mantou rules commands — list and show."""

from __future__ import annotations

import sys
from pathlib import Path

import click

import mantou.scanner as _scanner
from mantou.engine import loader


@click.group("rules")
def rules_cmd() -> None:
    """Inspect loaded rules."""


@rules_cmd.command("list")
@click.option(
    "--rules", "rules_dir", default=None, type=click.Path(), help="Rules directory override."
)
@click.option("--format", "fmt", default="table", type=click.Choice(["table", "json"]))
def rules_list(rules_dir: str | None, fmt: str) -> None:
    """List all enabled rules."""
    rdir = Path(rules_dir) if rules_dir else _scanner._RULES_DIR
    rules = loader.load(rdir)

    if fmt == "json":
        import json

        click.echo(json.dumps([r.model_dump() for r in rules], indent=2))
        return

    if not rules:
        click.echo("No rules loaded.")
        return

    header = f"{'ID':<12} {'SEV':<10} {'CATEGORY':<15} {'TITLE'}"
    click.echo(header)
    click.echo("-" * 70)
    for r in rules:
        click.echo(
            f"{r.id:<12} {r.finding.severity:<10} {r.finding.category:<15} {r.finding.title}"
        )


@rules_cmd.command("show")
@click.argument("rule_id")
@click.option(
    "--rules", "rules_dir", default=None, type=click.Path(), help="Rules directory override."
)
def rules_show(rule_id: str, rules_dir: str | None) -> None:
    """Show details for a specific rule ID."""
    rdir = Path(rules_dir) if rules_dir else _scanner._RULES_DIR
    rules = loader.load(rdir)

    matched = [r for r in rules if r.id == rule_id]
    if not matched:
        click.echo(f"Rule {rule_id!r} not found.", err=True)
        sys.exit(2)

    r = matched[0]
    click.echo(f"ID:          {r.id}")
    click.echo(f"Severity:    {r.finding.severity}")
    click.echo(f"Category:    {r.finding.category}")
    click.echo("Enabled:     yes")
    click.echo(f"Description: {r.description}")
    click.echo(f"Tags:        {', '.join(r.tags)}")
    click.echo(f"\nTarget:      type={r.target.type}")
    click.echo(f"Probe:       type={r.probe.type}")
    click.echo(f"\nTitle:       {r.finding.title}")
    click.echo(f"Detail:      {r.finding.detail}")
    click.echo(f"Remediation: {r.finding.remediation}")
