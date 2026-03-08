"""Text finder — regex content probes against workspace prompt files."""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mantou.discovery import OpenClawContext
    from mantou.engine.loader import ProbeSpec, TargetSpec

MAX_FILE_SIZE = 1_048_576  # 1 MB

# Compiled secret patterns for PROMPT-001
_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----"),
    re.compile(r"(?i)(api[_-]?key|api[_-]?token|secret[_-]?key)\s*[=:]\s*['\"]?\w{16,}"),
    re.compile(r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
]


def _redact_line(line: str) -> str:
    """Replace secret values in a matched line with [REDACTED]."""
    for pattern in _SECRET_PATTERNS:
        line = pattern.sub("[REDACTED]", line)
    return line


def _probe_file(
    path: Path,
    patterns: list[re.Pattern[str]],
    require_all: bool,
    context: OpenClawContext,
) -> tuple[bool, str]:
    """Return (fired, evidence_line). evidence is redacted."""
    from mantou.engine.runner import ProbeError

    if not path.exists():
        return False, ""

    if path.stat().st_size > MAX_FILE_SIZE:
        raise ProbeError(
            rule_id="",
            reason="unreadable_file",
            detail=f"File too large to scan: {path} ({path.stat().st_size} bytes)",
        )

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except PermissionError as exc:
        raise ProbeError(rule_id="", reason="permission_denied", detail=str(exc)) from exc

    fired_patterns: list[re.Pattern[str]] = []
    first_evidence = ""

    for pattern in patterns:
        match = pattern.search(content)
        if match:
            fired_patterns.append(pattern)
            if not first_evidence:
                line = content[: match.start()].count("\n")
                raw_line = content.splitlines()[line] if content.splitlines() else ""
                first_evidence = _redact_line(raw_line)

    if require_all:
        fired = len(fired_patterns) == len(patterns)
    else:
        fired = len(fired_patterns) > 0

    return fired, first_evidence


def probe(target: TargetSpec, probe_spec: ProbeSpec, context: OpenClawContext) -> Any:
    from mantou.engine.runner import ProbeError

    probe_type = probe_spec.type

    if probe_type not in ("regex_any", "regex_all"):
        raise ProbeError(
            rule_id="",
            reason="unsupported_platform",
            detail=f"Text finder does not support probe type: {probe_type!r}",
        )

    require_all = probe_type == "regex_all"
    raw_patterns: list[str] = probe_spec.patterns or []
    if not raw_patterns and probe_spec.pattern:
        raw_patterns = [probe_spec.pattern]

    if not raw_patterns:
        raw_patterns = [p.pattern for p in _SECRET_PATTERNS]

    compiled = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in raw_patterns]

    # Determine which files to scan
    files_to_scan: list[Path] = []
    if target.path:
        files_to_scan = [Path(target.path).expanduser()]
    elif target.paths:
        files_to_scan = [Path(p).expanduser() for p in target.paths]
    elif context.prompt_files:
        files_to_scan = list(context.prompt_files)

    all_evidence: list[str] = []
    any_fired = False

    for file_path in files_to_scan:
        fired, evidence = _probe_file(file_path, compiled, require_all, context)
        if fired:
            any_fired = True
            if evidence:
                all_evidence.append(f"{file_path.name}: {evidence}")

    if require_all:
        # For regex_all we report whether all patterns fired in any file
        return any_fired
    return any_fired
