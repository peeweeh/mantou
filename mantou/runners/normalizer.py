"""Normalize parsed Phase 2 tool findings into canonical Finding objects."""

from __future__ import annotations

import re

from mantou.schema import Finding

SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "critical",
    "WARN": "high",
    "WARNING": "high",
    "warning": "high",
    "INFO": "info",
    "info": "info",
    "error": "critical",
}

CATEGORY_MAP: dict[str, str] = {
    "doctor": "config",
    "security_audit": "config",
    "security_audit_deep": "config",
    "status": "runtime",
    "daemon_status": "runtime",
    "gateway_status": "network",
}

PREFIX_MAP: dict[str, str] = {
    "doctor": "DOC",
    "security_audit": "AUDIT",
    "security_audit_deep": "AUDIT",
    "status": "STAT",
    "daemon_status": "STAT",
    "gateway_status": "STAT",
}

RESOURCE_MAP: dict[str, str] = {
    "doctor": "command://openclaw doctor",
    "security_audit": "command://openclaw security audit",
    "security_audit_deep": "command://openclaw security audit --deep",
    "status": "command://openclaw status",
    "daemon_status": "command://openclaw daemon status",
    "gateway_status": "command://openclaw gateway status",
}


def normalize(command_id: str, parsed: list[dict[str, str]]) -> list[Finding]:
    if not parsed:
        return []

    out: list[Finding] = []
    prefix = PREFIX_MAP.get(command_id, "TOOL")
    category = CATEGORY_MAP.get(command_id, "config")
    resource = RESOURCE_MAP.get(command_id, f"command://openclaw {command_id}")

    for i, item in enumerate(parsed, start=1):
        sev = SEVERITY_MAP.get(item.get("raw_severity", ""), "medium")
        out.append(
            Finding(
                id=f"{prefix}-{i:03d}",
                source=command_id,  # type: ignore[arg-type]
                phase=2,
                severity=sev,  # type: ignore[arg-type]
                category=category,  # type: ignore[arg-type]
                resource=resource,
                title=item.get("title", "Tool finding"),
                detail=item.get("detail", ""),
                evidence=_redact(item.get("evidence_excerpt", "")),
                remediation=item.get("remediation", "Review and remediate."),
            )
        )

    return out


def _redact(text: str) -> str:
    redacted = text
    redacted = re.sub(r"sk-[A-Za-z0-9]+", "[REDACTED]", redacted)
    redacted = re.sub(r"\b[A-Za-z0-9+/]{32,}\b", "[REDACTED]", redacted)
    redacted = re.sub(
        r"(?i)(token|secret|password|api_key)\s*[:=]\s*\S+",
        r"\1=[REDACTED]",
        redacted,
    )
    return redacted
