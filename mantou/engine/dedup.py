"""Deduplicate and correlate Phase 1 + Phase 2 findings."""

from __future__ import annotations

import re

from mantou.schema import Finding

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def escalate(s1: str, s2: str) -> str:
    def _idx(s: str) -> int:
        return SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else 2

    higher = s1 if _idx(s1) >= _idx(s2) else s2
    idx = _idx(higher)
    return SEVERITY_ORDER[min(idx + 1, len(SEVERITY_ORDER) - 1)]


def dedup(static_findings: list[Finding], tool_findings: list[Finding]) -> list[Finding]:
    if not static_findings and not tool_findings:
        return []

    out = list(static_findings) + list(tool_findings)

    static_index: dict[tuple[str, str], Finding] = {}
    for f in static_findings:
        static_index[(f.category, _normalize_title(f.title))] = f

    dedup_findings: list[Finding] = []
    n = 1
    for tf in tool_findings:
        key = (tf.category, _normalize_title(tf.title))
        sf = static_index.get(key)
        if sf is None:
            continue

        dedup_findings.append(
            Finding(
                id=f"DEDUP-{n:03d}",
                source="dedup",  # type: ignore[arg-type]
                phase=2,
                severity=escalate(sf.severity, tf.severity),  # type: ignore[arg-type]
                category=sf.category,
                resource=sf.resource,
                title=f"[Confirmed] {sf.title}",
                detail=f"Static scan and tool audit both detected: {sf.detail}",
                evidence=f"Static: {sf.evidence} | Tool: {tf.evidence}".strip(),
                remediation=sf.remediation,
            )
        )
        n += 1

    out.extend(dedup_findings)
    return out


def _normalize_title(title: str) -> str:
    text = title.lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()
