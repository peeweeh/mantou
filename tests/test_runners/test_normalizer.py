from __future__ import annotations

from mantou.runners.normalizer import normalize


def _parsed(
    sev: str, title: str = "t", detail: str = "d", rem: str = "r", ev: str = "e"
) -> dict[str, str]:
    return {
        "raw_severity": sev,
        "title": title,
        "detail": detail,
        "remediation": rem,
        "section": "s",
        "evidence_excerpt": ev,
    }


def test_normalize_doctor_warning() -> None:
    out = normalize("doctor", [_parsed("warning")])
    assert out[0].severity == "medium"
    assert out[0].phase == 2
    assert out[0].source == "doctor"


def test_normalize_warn_stays_high() -> None:
    out = normalize("security_audit", [_parsed("WARN")])
    assert out[0].severity == "high"


def test_normalize_security_audit_critical() -> None:
    out = normalize("security_audit", [_parsed("CRITICAL")])
    assert out[0].severity == "critical"


def test_normalize_unknown_severity_defaults_medium() -> None:
    out = normalize("doctor", [_parsed("UNKNOWN")])
    assert out[0].severity == "medium"


def test_normalize_ids_sequential() -> None:
    out = normalize("doctor", [_parsed("INFO"), _parsed("INFO"), _parsed("INFO")])
    assert [f.id for f in out] == ["DOC-001", "DOC-002", "DOC-003"]


def test_normalize_evidence_redacted() -> None:
    out = normalize("doctor", [_parsed("INFO", ev="token=sk-abc123")])
    assert "[REDACTED]" in out[0].evidence


def test_normalize_empty_list_returns_empty() -> None:
    assert normalize("doctor", []) == []


def test_normalize_category_from_command_id() -> None:
    out = normalize("gateway_status", [_parsed("INFO")])
    assert out[0].category == "network"
