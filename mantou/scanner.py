"""Top-level scan orchestrator."""

from __future__ import annotations

import platform
import time
from dataclasses import dataclass, field
from pathlib import Path

from mantou import __version__
from mantou.discovery import OpenClawContext
from mantou.engine import loader, runner
from mantou.schema import (
    OpenClawInfo,
    PlatformInfo,
    ScanResult,
    build_summary,
)

_RULES_DIR = Path(__file__).parent / "rules"
_RULESET_VERSION = "0.1.0"


@dataclass
class ScanOptions:
    min_severity: str = "low"
    exit_on: str | None = None
    no_os_probes: bool = False
    redact_secrets: bool = True
    max_file_size: int = 1_048_576
    include_info: bool = False
    rules_dir: Path = field(default_factory=lambda: _RULES_DIR)


def run(context: OpenClawContext, options: ScanOptions | None = None) -> ScanResult:
    if options is None:
        options = ScanOptions()

    start_ms = time.monotonic()

    rules = loader.load(options.rules_dir)
    finder_registry = runner.FinderRegistry(context)
    findings, failures = runner.run_all(rules, context, finder_registry)

    duration_ms = int((time.monotonic() - start_ms) * 1000)

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
