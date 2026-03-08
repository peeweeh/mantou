"""conftest.py — shared fixtures for all test modules."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def insecure_config(tmp_path: Path) -> Path:
    """Write the insecure openclaw fixture into a tmp dir and return its path."""
    src = FIXTURES_DIR / "openclaw-insecure.json"
    dest = tmp_path / "openclaw.json"
    dest.write_text(src.read_text())
    return dest


@pytest.fixture
def secure_config(tmp_path: Path) -> Path:
    """Write the secure openclaw fixture into a tmp dir and return its path."""
    src = FIXTURES_DIR / "openclaw-secure.json"
    dest = tmp_path / "openclaw.json"
    dest.write_text(src.read_text())
    return dest


@pytest.fixture
def mock_context(insecure_config: Path, tmp_path: Path) -> Any:
    """Return a minimal OpenClawContext pointing at the insecure fixture."""
    from mantou.discovery import OpenClawContext

    return OpenClawContext(
        config_path=insecure_config,
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


@pytest.fixture
def mock_context_secure(secure_config: Path, tmp_path: Path) -> Any:
    """Return a minimal OpenClawContext pointing at the secure fixture."""
    from mantou.discovery import OpenClawContext

    return OpenClawContext(
        config_path=secure_config,
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


@pytest.fixture
def rules_dir() -> Path:
    """Return the path to the bundled rules directory."""
    from mantou import scanner as _s

    return _s._RULES_DIR
