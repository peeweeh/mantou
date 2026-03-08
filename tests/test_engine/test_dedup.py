from __future__ import annotations

from mantou.engine.dedup import dedup, escalate
from mantou.schema import Finding


def _f(id_: str, source: str, sev: str, cat: str, title: str) -> Finding:
    return Finding(
        id=id_,
        source=source,  # type: ignore[arg-type]
        phase=1 if source == "static" else 2,
        severity=sev,  # type: ignore[arg-type]
        category=cat,  # type: ignore[arg-type]
        resource="file://x",
        title=title,
        detail="d",
        evidence="e",
        remediation="r",
    )


def test_no_overlap_returns_all_unchanged() -> None:
    s = [_f("A", "static", "low", "config", "Alpha")]
    t = [_f("B", "doctor", "high", "network", "Beta")]
    out = dedup(s, t)
    assert len(out) == 2


def test_overlap_adds_dedup_finding() -> None:
    s = [_f("A", "static", "medium", "config", "Same title")]
    t = [_f("B", "doctor", "high", "config", "Same title")]
    out = dedup(s, t)
    assert len(out) == 3
    assert out[-1].id == "DEDUP-001"


def test_escalated_severity_bumped() -> None:
    assert escalate("medium", "medium") == "high"


def test_escalated_severity_capped_at_critical() -> None:
    assert escalate("critical", "critical") == "critical"


def test_multiple_overlaps() -> None:
    s = [_f("A", "static", "low", "config", "One"), _f("C", "static", "low", "config", "Two")]
    t = [_f("B", "doctor", "low", "config", "One"), _f("D", "doctor", "low", "config", "Two")]
    out = dedup(s, t)
    assert len(out) == 6
    assert out[-2].id == "DEDUP-001"
    assert out[-1].id == "DEDUP-002"


def test_empty_inputs_returns_empty() -> None:
    assert dedup([], []) == []


def test_dedup_id_sequential() -> None:
    s = [_f("A", "static", "low", "config", "One"), _f("C", "static", "low", "config", "Two")]
    t = [_f("B", "doctor", "low", "config", "One"), _f("D", "doctor", "low", "config", "Two")]
    out = dedup(s, t)
    assert [f.id for f in out if f.id.startswith("DEDUP-")] == ["DEDUP-001", "DEDUP-002"]
