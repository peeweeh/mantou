"""Adapter for `openclaw security audit` output."""

from __future__ import annotations

import re

from mantou.runners.adapters.base import AbstractAdapter, ParsedToolFinding
from mantou.runners.tool_runner import RawToolResult


class SecurityAuditAdapter(AbstractAdapter):
    command_id = "security_audit"

    _HEADER_PREFIXES = (
        "Security audit",
        "Summary:",
        "Full report:",
        "Deep probe:",
    )

    def parse(self, result: RawToolResult) -> list[ParsedToolFinding]:
        text = result.stdout.strip()
        if not text:
            return []

        lines = text.splitlines()
        findings: list[ParsedToolFinding] = []
        current_sev = ""
        current_title = ""
        body: list[str] = []

        def flush() -> None:
            nonlocal current_sev, current_title, body
            if not current_sev or not current_title:
                return
            detail_lines: list[str] = []
            remediation = "Review the audit output and apply recommended remediation."
            for raw in body:
                stripped = raw.strip()
                if stripped.startswith("Fix: "):
                    remediation = stripped.replace("Fix: ", "", 1).strip()
                elif stripped:
                    detail_lines.append(stripped)
            findings.append(
                ParsedToolFinding(
                    raw_severity=current_sev,
                    title=current_title,
                    detail=" ".join(detail_lines).strip(),
                    remediation=remediation,
                    section="Security audit",
                    evidence_excerpt="\n".join(([f"{current_sev} {current_title}"] + body)[:3]),
                )
            )
            current_sev = ""
            current_title = ""
            body = []

        for line in lines:
            if any(line.startswith(prefix) for prefix in self._HEADER_PREFIXES):
                continue
            m = re.match(r"^\s*(CRITICAL|WARN|INFO)\s+(.+)$", line)
            if m:
                flush()
                current_sev = m.group(1)
                current_title = m.group(2).strip()
                continue
            if current_sev:
                body.append(line)

        flush()
        return findings
