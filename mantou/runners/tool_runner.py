"""Phase 2 tool runner with strict allowlist and safe subprocess handling."""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass

from mantou.schema import PartialFailure

TOOL_COMMANDS: dict[str, list[str]] = {
    "doctor": ["openclaw", "doctor"],
    "security_audit": ["openclaw", "security", "audit"],
    "security_audit_deep": ["openclaw", "security", "audit", "--deep"],
    "status": ["openclaw", "status"],
    "daemon_status": ["openclaw", "daemon", "status"],
    "gateway_status": ["openclaw", "gateway", "status"],
}


@dataclass
class RawToolResult:
    command_id: str
    argv: list[str]
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    timed_out: bool


def run_tool(command_id: str, timeout_s: int = 10) -> RawToolResult:
    if command_id not in TOOL_COMMANDS:
        raise ValueError(f"Unknown command_id: {command_id!r}")

    argv = TOOL_COMMANDS[command_id]
    start = time.monotonic()

    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            shell=False,
        )
        duration_ms = int((time.monotonic() - start) * 1000)
        return RawToolResult(
            command_id=command_id,
            argv=argv,
            stdout=result.stdout.strip(),
            stderr=result.stderr.strip(),
            exit_code=result.returncode,
            duration_ms=duration_ms,
            timed_out=False,
        )
    except subprocess.TimeoutExpired as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        return RawToolResult(
            command_id=command_id,
            argv=argv,
            stdout=(exc.stdout or "").strip() if isinstance(exc.stdout, str) else "",
            stderr=(exc.stderr or "").strip() if isinstance(exc.stderr, str) else "",
            exit_code=-1,
            duration_ms=duration_ms,
            timed_out=True,
        )
    except FileNotFoundError:
        duration_ms = int((time.monotonic() - start) * 1000)
        return RawToolResult(
            command_id=command_id,
            argv=argv,
            stdout="",
            stderr="openclaw not found",
            exit_code=-2,
            duration_ms=duration_ms,
            timed_out=False,
        )


def run_tool_safe(command_id: str, timeout_s: int = 10) -> RawToolResult | PartialFailure:
    if os.environ.get("MANTOU_SKIP_TOOLS"):
        return PartialFailure(
            rule_id="TOOL_RUNNER",
            reason="unsupported_platform",
            detail="MANTOU_SKIP_TOOLS set",
        )

    result = run_tool(command_id, timeout_s=timeout_s)
    if result.exit_code == -2:
        return PartialFailure(
            rule_id="TOOL_RUNNER",
            reason="unsupported_platform",
            detail="openclaw not on PATH",
        )

    return result
