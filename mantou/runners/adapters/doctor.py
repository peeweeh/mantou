"""Adapter for `openclaw doctor` output."""

from __future__ import annotations

import re

from mantou.runners.adapters.base import AbstractAdapter, ParsedToolFinding
from mantou.runners.tool_runner import RawToolResult


class DoctorAdapter(AbstractAdapter):
    command_id = "doctor"

    def parse(self, result: RawToolResult) -> list[ParsedToolFinding]:
        text = result.stdout.strip()
        if not text:
            return []

        lines = [self._clean_line(line) for line in text.splitlines()]
        findings: list[ParsedToolFinding] = []
        section = "Doctor warnings"
        bullets: list[str] = []
        current = ""

        for line in lines:
            if not line:
                continue
            if line.lower().startswith("doctor "):
                section = line
                continue
            if line.startswith("-"):
                if current:
                    bullets.append(current.strip())
                current = line.lstrip("- ").strip()
            elif current:
                current = f"{current} {line.strip()}"

        if current:
            bullets.append(current.strip())

        for b in bullets:
            detail, remediation = self._split_detail_remediation(b)
            evidence = b[:240]
            findings.append(
                ParsedToolFinding(
                    raw_severity="warning",
                    title=self._title_from_bullet(detail),
                    detail=detail,
                    remediation=remediation,
                    section=section,
                    evidence_excerpt=evidence,
                )
            )

        return findings

    def _clean_line(self, line: str) -> str:
        cleaned = line.strip()
        cleaned = re.sub(r"^[│◇├─╮╯\s]+", "", cleaned)
        cleaned = re.sub(r"[│╮╯]+$", "", cleaned)
        return cleaned.strip()

    def _split_detail_remediation(self, bullet: str) -> tuple[str, str]:
        if ". " in bullet:
            first, rest = bullet.split(". ", 1)
            return first.strip() + ".", rest.strip()
        return bullet, "Review and apply the suggested configuration fix."

    def _title_from_bullet(self, detail: str) -> str:
        match = re.search(r"([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+)", detail)
        if match:
            return f"Doctor warning for {match.group(1)}"
        return "Doctor warning"
