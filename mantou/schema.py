"""Canonical Pydantic models for all Mantou findings and scan results."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class Finding(BaseModel):
    id: str
    source: Literal[
        "static",
        "doctor",
        "security_audit",
        "security_audit_deep",
        "status",
        "daemon_status",
        "gateway_status",
        "dedup",
        "llm",
    ]
    phase: int
    severity: Literal["critical", "high", "medium", "low", "info"]
    category: Literal[
        "config", "network", "permissions", "secrets", "skills", "runtime", "data_retention"
    ]
    resource: str
    title: str
    detail: str
    evidence: str
    remediation: str


class PartialFailure(BaseModel):
    rule_id: str
    reason: Literal[
        "unreadable_file",
        "malformed_json",
        "permission_denied",
        "command_timeout",
        "unsupported_platform",
    ]
    detail: str


class ScanSummary(BaseModel):
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class PlatformInfo(BaseModel):
    os: Literal["darwin", "linux", "windows"]
    release: str
    arch: str
    container: bool = False
    docker_host: bool = False
    wsl: bool = False


class OpenClawInfo(BaseModel):
    detected: bool
    version: str | None = None
    mode: Literal["local", "gateway", "vps", "unknown"] = "unknown"
    status: Literal["unknown", "not_detected", "detected_config_only", "offline", "online"] = (
        "unknown"
    )


class ScanResult(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    phase: int = 1
    scan_mode: Literal["cli", "daemon"] = "cli"
    mantou_version: str
    ruleset_version: str
    duration_ms: int
    platform: PlatformInfo
    openclaw: OpenClawInfo
    partial_failures: list[PartialFailure] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)


def build_summary(findings: list[Finding]) -> ScanSummary:
    counts: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    for f in findings:
        counts[f.severity] += 1
    return ScanSummary(total=len(findings), **counts)  # type: ignore[arg-type]


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def severity_gte(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(threshold, 0)


ProbeResult = Any
