"""Tests for mantou.finders.text path resolution and regex probing."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def _make_context(workspace_dir: Path) -> Any:
    from mantou.discovery import OpenClawContext

    return OpenClawContext(
        config_path=None,
        openclaw_dir=workspace_dir,
        workspace_dir=workspace_dir,
        prompt_files=[],
        sessions_dir=None,
        logs_dir=None,
        credentials_dir=None,
        root_override=None,
        vm_user=None,
        os_probes_disabled=True,
    )


def test_text_probe_resolves_relative_to_workspace(tmp_path: Path) -> None:
    from mantou.engine.loader import ProbeSpec, TargetSpec
    from mantou.finders.text import probe

    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services:\n  app:\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"
    )

    ctx = _make_context(tmp_path)
    target = TargetSpec(type="text", path="docker-compose.yml")
    probe_spec = ProbeSpec(type="regex_any", patterns=[r"/var/run/docker\.sock"])

    assert probe(target, probe_spec, ctx) is True


def test_text_probe_missing_relative_file_returns_false(tmp_path: Path) -> None:
    from mantou.engine.loader import ProbeSpec, TargetSpec
    from mantou.finders.text import probe

    ctx = _make_context(tmp_path)
    target = TargetSpec(type="text", path="docker-compose.yml")
    probe_spec = ProbeSpec(type="regex_any", patterns=[r"/var/run/docker\.sock"])

    assert probe(target, probe_spec, ctx) is False
