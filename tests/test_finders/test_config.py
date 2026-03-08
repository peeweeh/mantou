"""Tests for mantou.finders.config."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest


def _make_context(config_path: Path, tmp_path: Path) -> Any:
    from mantou.discovery import OpenClawContext

    return OpenClawContext(
        config_path=config_path,
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


def _make_target(json_path: str) -> Any:
    from mantou.engine.loader import TargetSpec

    return TargetSpec(type="json", path=json_path)


def _make_probe(probe_type: str, **kwargs: Any) -> Any:
    from mantou.engine.loader import ProbeSpec

    return ProbeSpec(type=probe_type, **kwargs)


def test_probe_returns_value(insecure_config: Path, tmp_path: Path) -> None:
    from mantou.finders.config import probe

    ctx = _make_context(insecure_config, tmp_path)
    result = probe(_make_target("$.gateway.bind"), _make_probe("value"), ctx)
    assert result == "0.0.0.0"


def test_probe_returns_none_for_missing_key(insecure_config: Path, tmp_path: Path) -> None:
    from mantou.finders.config import probe

    ctx = _make_context(insecure_config, tmp_path)
    result = probe(_make_target("$.nonexistent.key"), _make_probe("value"), ctx)
    assert result is None


def test_probe_key_absent_or_empty_absent(insecure_config: Path, tmp_path: Path) -> None:
    """Missing key => key_absent_or_empty returns True."""
    from mantou.finders.config import probe

    ctx = _make_context(insecure_config, tmp_path)
    result = probe(_make_target("$.tools.shell.denylist"), _make_probe("key_absent_or_empty"), ctx)
    assert result is True


def test_probe_key_absent_or_empty_empty_list(tmp_path: Path) -> None:
    """Empty list => key_absent_or_empty returns True."""
    from mantou.finders.config import probe

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(json.dumps({"tools": {"shell": {"denylist": []}}}))
    ctx = _make_context(cfg, tmp_path)
    result = probe(_make_target("$.tools.shell.denylist"), _make_probe("key_absent_or_empty"), ctx)
    assert result is True


def test_probe_key_absent_or_empty_has_value(tmp_path: Path) -> None:
    """Non-empty list => key_absent_or_empty returns False."""
    from mantou.finders.config import probe

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(json.dumps({"tools": {"shell": {"denylist": ["rm -rf"]}}}))
    ctx = _make_context(cfg, tmp_path)
    result = probe(_make_target("$.tools.shell.denylist"), _make_probe("key_absent_or_empty"), ctx)
    assert result is False


def test_probe_contains_value_root(insecure_config: Path, tmp_path: Path) -> None:
    """insecure config has allowRead=['/'] — contains_value returns True."""
    from mantou.finders.config import probe

    ctx = _make_context(insecure_config, tmp_path)
    result = probe(
        _make_target("$.tools.filesystem.allowRead"),
        _make_probe("contains_value", value="/"),
        ctx,
    )
    assert result is True


def test_probe_contains_value_no_root(secure_config: Path, tmp_path: Path) -> None:
    """secure config does not have '/' in allowRead — contains_value returns False."""
    from mantou.finders.config import probe

    ctx = _make_context(secure_config, tmp_path)
    result = probe(
        _make_target("$.tools.filesystem.allowRead"),
        _make_probe("contains_value", value="/"),
        ctx,
    )
    assert result is False


def test_probe_key_absent_or_missing_paths_absent(insecure_config: Path, tmp_path: Path) -> None:
    """deny key absent => all required paths are missing => True."""
    from mantou.finders.config import probe

    ctx = _make_context(insecure_config, tmp_path)
    result = probe(
        _make_target("$.tools.filesystem.deny"),
        _make_probe("key_absent_or_missing_paths", paths=["~/.ssh", "~/.aws"]),
        ctx,
    )
    assert result is True


def test_probe_key_absent_or_missing_paths_present(secure_config: Path, tmp_path: Path) -> None:
    """secure config has all required paths => False."""
    from mantou.finders.config import probe

    ctx = _make_context(secure_config, tmp_path)
    result = probe(
        _make_target("$.tools.filesystem.deny"),
        _make_probe("key_absent_or_missing_paths", paths=["~/.ssh", "~/.aws"]),
        ctx,
    )
    assert result is False


def test_probe_raises_on_missing_file(tmp_path: Path) -> None:
    from mantou.engine.runner import ProbeError
    from mantou.finders.config import probe

    ctx = _make_context(tmp_path / "nonexistent.json", tmp_path)
    with pytest.raises(ProbeError):
        probe(_make_target("$.gateway.bind"), _make_probe("value"), ctx)


def test_probe_raises_on_malformed_json(tmp_path: Path) -> None:
    from mantou.engine.runner import ProbeError
    from mantou.finders.config import probe

    cfg = tmp_path / "openclaw.json"
    cfg.write_text("not json {{{")
    ctx = _make_context(cfg, tmp_path)
    with pytest.raises(ProbeError):
        probe(_make_target("$.gateway.bind"), _make_probe("value"), ctx)
