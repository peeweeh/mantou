from __future__ import annotations

from pathlib import Path

import pytest

from mantou.runners.adapters import get_adapter
from mantou.runners.tool_runner import RawToolResult

FIX = Path(__file__).parents[1] / "fixtures" / "tool_output"


def _result(command_id: str, text: str) -> RawToolResult:
    return RawToolResult(
        command_id=command_id,
        argv=["openclaw", command_id],
        stdout=text,
        stderr="",
        exit_code=0,
        duration_ms=10,
        timed_out=False,
    )


def test_doctor_parses_warnings() -> None:
    adapter = get_adapter("doctor")
    text = (FIX / "doctor-warnings.txt").read_text()
    parsed = adapter.parse(_result("doctor", text))
    assert len(parsed) == 3
    assert all(p["raw_severity"] == "warning" for p in parsed)


def test_doctor_empty_returns_empty() -> None:
    adapter = get_adapter("doctor")
    text = (FIX / "doctor-empty.txt").read_text()
    parsed = adapter.parse(_result("doctor", text))
    assert parsed == []


def test_doctor_multiline_bullet_concatenated() -> None:
    adapter = get_adapter("doctor")
    text = "◇  Doctor warnings\n│  - a.b is unsafe\n│    use allowlist now"
    parsed = adapter.parse(_result("doctor", text))
    assert len(parsed) == 1
    assert (
        "use allowlist now" in parsed[0]["detail"]
        or "use allowlist now" in parsed[0]["remediation"]
    )


def test_security_audit_parses_criticals() -> None:
    adapter = get_adapter("security_audit")
    text = (FIX / "security-audit-4crit.txt").read_text()
    parsed = adapter.parse(_result("security_audit", text))
    assert len(parsed) == 7
    assert len([p for p in parsed if p["raw_severity"] == "CRITICAL"]) == 4


def test_security_audit_empty_returns_empty() -> None:
    adapter = get_adapter("security_audit")
    text = (FIX / "security-audit-clean.txt").read_text()
    parsed = adapter.parse(_result("security_audit", text))
    assert parsed == []


def test_security_audit_fix_line_goes_to_remediation() -> None:
    adapter = get_adapter("security_audit")
    text = "  WARN foo\n    detail\n    Fix: do thing"
    parsed = adapter.parse(_result("security_audit", text))
    assert parsed[0]["remediation"] == "do thing"


def test_get_adapter_unknown_raises() -> None:
    with pytest.raises(ValueError):
        get_adapter("bad_cmd")
