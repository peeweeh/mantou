"""Top-level scan orchestrator."""

from __future__ import annotations

import os
import platform
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from mantou import __version__
from mantou.discovery import OpenClawContext
from mantou.engine import loader, runner
from mantou.engine.dedup import dedup
from mantou.runners.adapters import get_adapter
from mantou.runners.normalizer import normalize
from mantou.runners.tool_runner import TOOL_COMMANDS, run_tool_safe
from mantou.schema import (
    Finding,
    OpenClawInfo,
    PartialFailure,
    PlatformInfo,
    ScanResult,
    build_summary,
)

_RULES_DIR = Path(__file__).parent / "rules"
_RULESET_VERSION = "0.1.0"
ProgressReporter = Callable[[str], None]


@dataclass
class ScanOptions:
    min_severity: str = "low"
    exit_on: str | None = None
    no_os_probes: bool = False
    redact_secrets: bool = True
    max_file_size: int = 1_048_576
    include_info: bool = False
    rules_dir: Path = field(default_factory=lambda: _RULES_DIR)


def run(
    context: OpenClawContext,
    options: ScanOptions | None = None,
    *,
    skip_tools: bool | None = None,
    progress: ProgressReporter | None = None,
) -> ScanResult:
    if options is None:
        options = ScanOptions()

    start_ms = time.monotonic()

    if progress:
        progress("Phase 1/2: running static checks")
    static_findings, static_failures = _run_phase1(context, options)

    if skip_tools is None:
        skip_tools = bool(os.environ.get("MANTOU_SKIP_TOOLS"))
    if skip_tools:
        if progress:
            progress("Phase 2/2: skipped tool checks")
        tool_findings: list[Finding] = []
        tool_failures = [
            PartialFailure(
                rule_id="TOOL_RUNNER",
                reason="unsupported_platform",
                detail="MANTOU_SKIP_TOOLS set",
            )
        ]
    else:
        if progress:
            progress("Phase 2/2: running OpenClaw tool checks")
        tool_findings, tool_failures = run_phase2(context)

    findings = dedup(static_findings, tool_findings)
    failures = static_failures + tool_failures

    duration_ms = int((time.monotonic() - start_ms) * 1000)
    if progress:
        progress(f"Scan complete in {duration_ms}ms")

    return ScanResult(
        mantou_version=__version__,
        ruleset_version=_RULESET_VERSION,
        duration_ms=duration_ms,
        platform=_detect_platform(context),
        openclaw=_openclaw_info(context),
        partial_failures=failures,
        findings=findings,
        summary=build_summary(findings),
    )


def run_tools_only(
    context: OpenClawContext,
    options: ScanOptions | None = None,
    *,
    progress: ProgressReporter | None = None,
) -> ScanResult:
    if options is None:
        options = ScanOptions()

    start_ms = time.monotonic()
    if progress:
        progress("Running OpenClaw tool checks")
    findings, failures = run_phase2(context)
    duration_ms = int((time.monotonic() - start_ms) * 1000)
    if progress:
        progress(f"Doctor complete in {duration_ms}ms")

    return ScanResult(
        mantou_version=__version__,
        ruleset_version=_RULESET_VERSION,
        duration_ms=duration_ms,
        platform=_detect_platform(context),
        openclaw=_openclaw_info(context),
        partial_failures=failures,
        findings=findings,
        summary=build_summary(findings),
    )


def _run_phase1(
    context: OpenClawContext,
    options: ScanOptions,
) -> tuple[list[Finding], list[PartialFailure]]:
    rules = loader.load(options.rules_dir)
    finder_registry = runner.FinderRegistry(context)
    return runner.run_all(rules, context, finder_registry)


def run_phase2(context: OpenClawContext) -> tuple[list[Finding], list[PartialFailure]]:
    findings: list[Finding] = []
    failures: list[PartialFailure] = []

    for command_id in TOOL_COMMANDS:
        result_or_failure = run_tool_safe(command_id)
        if isinstance(result_or_failure, PartialFailure):
            failures.append(result_or_failure)
            continue

        if result_or_failure.exit_code != 0 and not result_or_failure.stdout:
            failures.append(
                PartialFailure(
                    rule_id=f"TOOL-{command_id}",
                    reason="unreadable_file",
                    detail=result_or_failure.stderr or "tool command failed",
                )
            )
            continue

        adapter = get_adapter(command_id)
        parsed = adapter.parse(result_or_failure)
        findings.extend(normalize(command_id, parsed))

    return findings, failures


def _detect_platform(context: OpenClawContext) -> PlatformInfo:
    is_container = Path("/.dockerenv").exists()
    is_wsl = False
    if context.platform == "linux":
        try:
            is_wsl = "microsoft" in Path("/proc/version").read_text(encoding="utf-8").lower()
        except OSError:
            pass

    return PlatformInfo(
        os=context.platform,  # type: ignore[arg-type]
        release=platform.release(),
        arch=platform.machine(),
        container=is_container,
        wsl=is_wsl,
    )


def _openclaw_info(context: OpenClawContext) -> OpenClawInfo:
    info = context.to_openclaw_info()
    if isinstance(info, OpenClawInfo):
        return info
    # Fallback
    if context.config_path is not None:
        return OpenClawInfo(detected=True, status="detected_config_only")
    return OpenClawInfo(detected=False, status="not_detected")
