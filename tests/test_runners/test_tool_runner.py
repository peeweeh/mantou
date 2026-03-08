from __future__ import annotations

import subprocess
from types import SimpleNamespace
from typing import Any

import pytest

from mantou.runners.tool_runner import run_tool, run_tool_safe


def test_unknown_command_id_raises() -> None:
    with pytest.raises(ValueError):
        run_tool("bad_cmd")


def test_skip_tools_env_returns_partial_failure(monkeypatch: Any) -> None:
    monkeypatch.setenv("MANTOU_SKIP_TOOLS", "1")
    out = run_tool_safe("doctor")
    assert out.rule_id == "TOOL_RUNNER"


def test_openclaw_not_found_returns_partial_failure(monkeypatch: Any) -> None:
    monkeypatch.delenv("MANTOU_SKIP_TOOLS", raising=False)

    def _raise(*_args: Any, **_kwargs: Any) -> Any:
        raise FileNotFoundError

    monkeypatch.setattr(subprocess, "run", _raise)
    out = run_tool_safe("doctor")
    assert out.rule_id == "TOOL_RUNNER"


def test_timeout_returns_timed_out_result(monkeypatch: Any) -> None:
    monkeypatch.delenv("MANTOU_SKIP_TOOLS", raising=False)

    def _timeout(*_args: Any, **_kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd=["openclaw"], timeout=1)

    monkeypatch.setattr(subprocess, "run", _timeout)
    out = run_tool("doctor", timeout_s=1)
    assert out.timed_out is True
    assert out.exit_code == -1


def test_successful_run_returns_raw_result(monkeypatch: Any) -> None:
    monkeypatch.delenv("MANTOU_SKIP_TOOLS", raising=False)

    def _ok(*_args: Any, **_kwargs: Any) -> Any:
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(subprocess, "run", _ok)
    out = run_tool_safe("doctor")
    assert out.exit_code == 0
    assert out.stdout == "ok"


def test_nonzero_exit_returns_raw_result(monkeypatch: Any) -> None:
    monkeypatch.delenv("MANTOU_SKIP_TOOLS", raising=False)

    def _bad(*_args: Any, **_kwargs: Any) -> Any:
        return SimpleNamespace(returncode=1, stdout="partial", stderr="err")

    monkeypatch.setattr(subprocess, "run", _bad)
    out = run_tool_safe("doctor")
    assert out.exit_code == 1
    assert out.stdout == "partial"
