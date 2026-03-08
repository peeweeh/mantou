"""Command finder — executes allowlisted commands and returns stdout."""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mantou.discovery import OpenClawContext
    from mantou.engine.loader import ProbeSpec, TargetSpec

COMMAND_TIMEOUT = 5  # seconds

# Hardcoded allowlist — no user-supplied commands ever
COMMAND_ALLOWLIST: dict[str, list[str]] = {
    "id_u": ["id", "-u"],
    "id_un": ["id", "-un"],
    "uname_s": ["uname", "-s"],
    "uname_m": ["uname", "-m"],
    "node_version": ["node", "--version"],
    "openclaw_version": ["openclaw", "--version"],
}

# Platform restrictions per command_id (None = all platforms)
COMMAND_PLATFORMS: dict[str, list[str] | None] = {
    "id_u": ["linux", "darwin"],
    "id_un": ["linux", "darwin"],
    "uname_s": ["linux", "darwin"],
    "uname_m": ["linux", "darwin"],
    "node_version": ["linux", "darwin"],
    "openclaw_version": ["linux", "darwin"],
}


def probe(target: TargetSpec, probe_spec: ProbeSpec, context: OpenClawContext) -> Any:
    from mantou.engine.runner import ProbeError

    command_id = target.command_id
    if not command_id:
        raise ProbeError(
            rule_id="",
            reason="unsupported_platform",
            detail="command target requires 'command_id'",
        )

    if command_id not in COMMAND_ALLOWLIST:
        raise ProbeError(
            rule_id="",
            reason="unsupported_platform",
            detail=f"Unknown command_id: {command_id!r} — not in allowlist",
        )

    # Platform filter — check target.platform first, then allowlist
    platform_filter = target.platform or COMMAND_PLATFORMS.get(command_id)
    if platform_filter and context.platform not in platform_filter:
        raise ProbeError(
            rule_id="",
            reason="unsupported_platform",
            detail=f"Command {command_id!r} not supported on platform {context.platform!r}",
        )

    # OS probes disabled in VM mode
    if getattr(context, "os_probes_disabled", False):
        raise ProbeError(
            rule_id="",
            reason="unsupported_platform",
            detail="OS probes are disabled in VM scan mode (--root). Use --allow-os-probes to override.",
        )

    cmd = COMMAND_ALLOWLIST[command_id]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT,
            shell=False,  # NEVER shell=True
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired as exc:
        raise ProbeError(
            rule_id="",
            reason="command_timeout",
            detail=f"Command {cmd!r} timed out after {COMMAND_TIMEOUT}s",
        ) from exc
    except FileNotFoundError as exc:
        raise ProbeError(
            rule_id="",
            reason="unreadable_file",
            detail=f"Command not found: {cmd[0]!r}",
        ) from exc
