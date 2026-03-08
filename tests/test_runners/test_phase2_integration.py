from __future__ import annotations

from typing import Any

from click.testing import CliRunner


def test_scan_skip_tools_returns_phase1_only(mock_context: Any, monkeypatch: Any) -> None:
    import mantou.scanner as scanner

    monkeypatch.setenv("MANTOU_SKIP_TOOLS", "1")
    result = scanner.run(mock_context)
    assert all(f.phase == 1 for f in result.findings)


def test_scan_phase2_findings_included(mock_context: Any, monkeypatch: Any) -> None:
    import mantou.scanner as scanner
    from mantou.runners.tool_runner import RawToolResult

    def _fake_run_tool_safe(command_id: str) -> Any:
        if command_id == "doctor":
            return RawToolResult(
                command_id="doctor",
                argv=["openclaw", "doctor"],
                stdout="◇  Doctor warnings\n- channels.discord.groupPolicy is open. set allowlist",
                stderr="",
                exit_code=0,
                duration_ms=1,
                timed_out=False,
            )
        return RawToolResult(command_id, ["openclaw"], "", "", 0, 1, False)

    monkeypatch.delenv("MANTOU_SKIP_TOOLS", raising=False)
    monkeypatch.setattr("mantou.scanner.run_tool_safe", _fake_run_tool_safe)

    result = scanner.run(mock_context)
    assert any(f.phase == 2 for f in result.findings)


def test_phase2_partial_failure_does_not_crash(mock_context: Any, monkeypatch: Any) -> None:
    import mantou.scanner as scanner
    from mantou.schema import PartialFailure

    monkeypatch.setattr(
        scanner,
        "run_phase2",
        lambda _ctx: ([], [PartialFailure(rule_id="x", reason="unsupported_platform", detail="d")]),
    )
    result = scanner.run(mock_context)
    assert len(result.partial_failures) >= 1


def test_dedup_applied_in_scan(mock_context: Any, monkeypatch: Any) -> None:
    import mantou.scanner as scanner
    from mantou.schema import Finding

    tool_finding = Finding(
        id="DOC-001",
        source="doctor",
        phase=2,
        severity="high",
        category="config",
        resource="command://openclaw doctor",
        title="Gateway authentication disabled",
        detail="d",
        evidence="e",
        remediation="r",
    )

    monkeypatch.setattr(scanner, "run_phase2", lambda _ctx: ([tool_finding], []))
    result = scanner.run(mock_context)
    assert any(f.id.startswith("DEDUP-") for f in result.findings)


def test_doctor_cli_command_runs(monkeypatch: Any) -> None:
    from mantou.cli.main import cli
    from mantou.schema import ScanResult

    def _fake_run_tools_only(_ctx: Any) -> ScanResult:
        from mantou.schema import OpenClawInfo, PlatformInfo, ScanSummary

        return ScanResult(
            mantou_version="0.1.0",
            ruleset_version="0.1.0",
            duration_ms=1,
            platform=PlatformInfo(os="darwin", release="x", arch="arm64"),
            openclaw=OpenClawInfo(detected=True, status="detected_config_only"),
            findings=[],
            partial_failures=[],
            summary=ScanSummary(),
        )

    monkeypatch.setattr("mantou.scanner.run_tools_only", _fake_run_tools_only)
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor", "--text", "--no-interactive"])
    assert result.exit_code == 0
