"""Tests for mantou.finders.command graceful fallback behavior."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any


def _make_context(tmp_path: Path, os_probes_disabled: bool = False) -> Any:
    from mantou.discovery import OpenClawContext

    return OpenClawContext(
        config_path=None,
        openclaw_dir=tmp_path,
        workspace_dir=tmp_path,
        prompt_files=[],
        sessions_dir=None,
        logs_dir=None,
        credentials_dir=None,
        root_override=None,
        vm_user=None,
        os_probes_disabled=os_probes_disabled,
    )


def _make_target(command_id: str) -> Any:
    from mantou.engine.loader import TargetSpec

    return TargetSpec(type="command", command_id=command_id)


def _make_probe() -> Any:
    from mantou.engine.loader import ProbeSpec

    return ProbeSpec(type="stdout")


def test_probe_returns_none_when_os_probes_disabled(tmp_path: Path) -> None:
    from mantou.finders.command import probe

    ctx = _make_context(tmp_path, os_probes_disabled=True)
    result = probe(_make_target("openclaw_version"), _make_probe(), ctx)
    assert result is None


def test_probe_returns_none_when_command_missing(tmp_path: Path, monkeypatch: Any) -> None:
    from mantou.finders.command import probe

    def _raise_not_found(*_args: Any, **_kwargs: Any) -> Any:
        raise FileNotFoundError("missing")

    monkeypatch.setattr("subprocess.run", _raise_not_found)

    ctx = _make_context(tmp_path)
    result = probe(_make_target("openclaw_version"), _make_probe(), ctx)
    assert result is None


def test_probe_returns_none_on_nonzero_exit(tmp_path: Path, monkeypatch: Any) -> None:
    from mantou.finders.command import probe

    def _fake_run(*_args: Any, **_kwargs: Any) -> Any:
        return SimpleNamespace(returncode=1, stdout="", stderr="error")

    monkeypatch.setattr("subprocess.run", _fake_run)

    ctx = _make_context(tmp_path)
    result = probe(_make_target("openclaw_version"), _make_probe(), ctx)
    assert result is None
