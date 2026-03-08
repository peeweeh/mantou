"""Tests for mantou.finders.filesystem."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest


def _make_context(tmp_path: Path) -> Any:
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
        os_probes_disabled=True,
    )


def _make_target(path: str, probe_type_hint: str | None = None) -> Any:
    from mantou.engine.loader import TargetSpec

    return TargetSpec(type="filesystem", path=path)


def _make_probe(probe_type: str, **kwargs: Any) -> Any:
    from mantou.engine.loader import ProbeSpec

    return ProbeSpec(type=probe_type, **kwargs)


def test_path_exists_true(tmp_path: Path) -> None:
    f = tmp_path / "test.txt"
    f.touch()
    from mantou.finders.filesystem import probe

    ctx = _make_context(tmp_path)
    target = _make_target(str(f))
    result = probe(target, _make_probe("path_exists"), ctx)
    assert result is True


def test_path_exists_false(tmp_path: Path) -> None:
    from mantou.finders.filesystem import probe

    ctx = _make_context(tmp_path)
    target = _make_target(str(tmp_path / "nope.txt"))
    result = probe(target, _make_probe("path_exists"), ctx)
    assert result is False


def test_exists_any_true(tmp_path: Path) -> None:
    f = tmp_path / "openclaw"
    f.mkdir()
    from mantou.finders.filesystem import probe

    ctx = _make_context(tmp_path)
    target = _make_target(str(f))
    result = probe(target, _make_probe("exists_any"), ctx)
    assert result is True


def test_exists_any_false(tmp_path: Path) -> None:
    from mantou.finders.filesystem import probe

    ctx = _make_context(tmp_path)
    target = _make_target(str(tmp_path / "missing"))
    result = probe(target, _make_probe("exists_any"), ctx)
    assert result is False


def test_stat_returns_dict(tmp_path: Path) -> None:
    f = tmp_path / "testfile"
    f.touch()
    os.chmod(f, 0o600)
    from mantou.finders.filesystem import probe

    ctx = _make_context(tmp_path)
    target = _make_target(str(f))
    result = probe(target, _make_probe("stat"), ctx)
    assert isinstance(result, dict)
    assert "mode" in result
    assert "owner" in result


@pytest.mark.skipif(os.getuid() == 0, reason="chmod world-readable not testable as root")
def test_stat_detects_world_readable(tmp_path: Path) -> None:
    f = tmp_path / "toopermissive"
    f.touch()
    os.chmod(f, 0o644)
    from mantou.engine.evaluator import evaluate
    from mantou.finders.filesystem import probe

    ctx = _make_context(tmp_path)
    result = probe(_make_target(str(f)), _make_probe("stat"), ctx)
    assert evaluate({"operator": "world_readable"}, result) is True


@pytest.mark.skipif(os.getuid() == 0, reason="chmod 600 not testable as root")
def test_stat_no_world_readable(tmp_path: Path) -> None:
    f = tmp_path / "private"
    f.touch()
    os.chmod(f, 0o600)
    from mantou.engine.evaluator import evaluate
    from mantou.finders.filesystem import probe

    ctx = _make_context(tmp_path)
    result = probe(_make_target(str(f)), _make_probe("stat"), ctx)
    assert evaluate({"operator": "world_readable"}, result) is False


def test_text_contains_true(tmp_path: Path) -> None:
    f = tmp_path / "mounts"
    f.write_text("overlay / ... docker.sock /var/lib/docker\n")
    from mantou.engine.loader import ProbeSpec, TargetSpec
    from mantou.finders.filesystem import probe

    ctx = _make_context(tmp_path)
    target = TargetSpec(type="filesystem", path=str(f))
    probe_spec = ProbeSpec(type="text_contains", keyword="docker.sock")
    result = probe(target, probe_spec, ctx)
    assert result is True


def test_text_contains_false(tmp_path: Path) -> None:
    f = tmp_path / "mounts"
    f.write_text("overlay / ext4 rw,relatime 0 0\n")
    from mantou.engine.loader import ProbeSpec, TargetSpec
    from mantou.finders.filesystem import probe

    ctx = _make_context(tmp_path)
    target = TargetSpec(type="filesystem", path=str(f))
    probe_spec = ProbeSpec(type="text_contains", keyword="docker.sock")
    result = probe(target, probe_spec, ctx)
    assert result is False
