"""OpenClaw path discovery — resolves config paths without probing files."""

from __future__ import annotations

import os
import platform
import sys
from pathlib import Path
from typing import Literal


class OpenClawContext:
    """Resolved paths and runtime context for a Mantou scan."""

    def __init__(
        self,
        config_path: Path | None = None,
        openclaw_dir: Path | None = None,
        workspace_dir: Path | None = None,
        prompt_files: list[Path] | None = None,
        sessions_dir: Path | None = None,
        logs_dir: Path | None = None,
        credentials_dir: Path | None = None,
        root_override: Path | None = None,
        vm_user: str | None = None,
        os_probes_disabled: bool = False,
    ) -> None:
        self.config_path = config_path
        self.openclaw_dir = openclaw_dir
        self.workspace_dir = workspace_dir
        self.prompt_files = prompt_files or []
        self.sessions_dir = sessions_dir
        self.logs_dir = logs_dir
        self.credentials_dir = credentials_dir
        self.root_override = root_override
        self.vm_user = vm_user
        self.os_probes_disabled = os_probes_disabled
        self.platform = _detect_platform_name()

    def to_openclaw_info(self) -> OpenClawInfoDict:
        from mantou.schema import OpenClawInfo

        if self.config_path is None:
            status = "not_detected"
            detected = False
        else:
            status = "detected_config_only"
            detected = True

        return OpenClawInfo(detected=detected, status=status)  # type: ignore[return-value]


# Type alias for return hint above
OpenClawInfoDict = object


def _detect_platform_name() -> Literal["darwin", "linux", "windows"]:
    system = platform.system().lower()
    if system == "darwin":
        return "darwin"
    if system == "linux":
        return "linux"
    return "windows"


_STANDARD_OPENCLAW_DIR = Path.home() / ".openclaw"
_PROMPT_FILENAMES = ["SOUL.md", "AGENTS.md", "TOOLS.md", "USER.md"]

_ENV_CONFIG = "MANTOU_CONFIG"
_ENV_WORKSPACE = "MANTOU_WORKSPACE"
_ENV_OPENCLAW_DIR = "MANTOU_OPENCLAW_DIR"
_ENV_ROOT = "MANTOU_ROOT"


def resolve(
    config_override: Path | None = None,
    workspace_override: Path | None = None,
    openclaw_dir_override: Path | None = None,
    root_override: Path | None = None,
    vm_user: str | None = None,
    allow_os_probes: bool = False,
    interactive: bool = True,
) -> OpenClawContext:
    """Resolve OpenClaw paths. Interactive fallback if stdin is a TTY and no path found."""

    # Root override (VM scan mode)
    root = root_override or (Path(os.environ[_ENV_ROOT]) if _ENV_ROOT in os.environ else None)
    os_probes_disabled = root is not None and not allow_os_probes

    # OpenClaw dir resolution
    openclaw_dir = _resolve_openclaw_dir(openclaw_dir_override, root)

    # Config path resolution
    config_path = _resolve_config_path(config_override, openclaw_dir)

    # Workspace dir
    workspace_dir = workspace_override or (
        Path(os.environ[_ENV_WORKSPACE]) if _ENV_WORKSPACE in os.environ else Path.cwd()
    )

    # Prompt files in workspace
    prompt_files = _find_prompt_files(workspace_dir)

    # Sub-dirs under openclaw_dir
    sessions_dir = (openclaw_dir / "sessions") if openclaw_dir else None
    logs_dir = (openclaw_dir / "logs") if openclaw_dir else None
    credentials_dir = (openclaw_dir / "channels") if openclaw_dir else None

    # Interactive fallback
    if config_path is None and interactive and sys.stdin.isatty() and root is None:
        config_path = _interactive_prompt()

    return OpenClawContext(
        config_path=config_path,
        openclaw_dir=openclaw_dir,
        workspace_dir=workspace_dir,
        prompt_files=prompt_files,
        sessions_dir=sessions_dir,
        logs_dir=logs_dir,
        credentials_dir=credentials_dir,
        root_override=root,
        vm_user=vm_user,
        os_probes_disabled=os_probes_disabled,
    )


def _resolve_openclaw_dir(override: Path | None, root: Path | None) -> Path | None:
    if override:
        return override.expanduser()
    if _ENV_OPENCLAW_DIR in os.environ:
        return Path(os.environ[_ENV_OPENCLAW_DIR]).expanduser()
    base = root / Path.home().relative_to("/") if root else Path.home()
    candidate = base / ".openclaw"
    return candidate if candidate.exists() else _STANDARD_OPENCLAW_DIR


def _resolve_config_path(override: Path | None, openclaw_dir: Path | None) -> Path | None:
    if override:
        p = override.expanduser()
        return p if p.exists() else None
    if _ENV_CONFIG in os.environ:
        p = Path(os.environ[_ENV_CONFIG]).expanduser()
        return p if p.exists() else None
    if openclaw_dir:
        candidate = openclaw_dir / "openclaw.json"
        return candidate if candidate.exists() else None
    return None


def _find_prompt_files(workspace_dir: Path) -> list[Path]:
    found: list[Path] = []
    for name in _PROMPT_FILENAMES:
        p = workspace_dir / name
        if p.exists():
            found.append(p)
    return found


def _interactive_prompt() -> Path | None:
    print("\nMantou could not find ~/.openclaw/openclaw.json")
    try:
        answer = input("Enter path to openclaw.json (or press Enter to skip): ").strip()
    except (EOFError, KeyboardInterrupt):
        return None
    if not answer:
        return None
    p = Path(answer).expanduser()
    return p if p.exists() else None
