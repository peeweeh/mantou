"""Tests for mantou.engine.runner — integration-level rule execution."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _write_rule(tmp_path: Path, rule: dict) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    f = tmp_path / "testrules.json"
    f.write_text(json.dumps([rule]))
    return tmp_path


def _base_rule(
    rule_id: str,
    target_type: str = "json",
    json_path: str = "$.gateway.bind",
    probe_type: str = "value",
    condition: dict | None = None,
) -> dict:
    return {
        "id": rule_id,
        "enabled": True,
        "description": "Test rule",
        "tags": [],
        "target": {"type": target_type, "path": json_path},
        "probe": {"type": probe_type},
        "condition": condition or {"operator": "equals", "value": "0.0.0.0"},
        "finding": {
            "severity": "critical",
            "category": "config",
            "title": "Test Finding",
            "detail": "Test detail",
            "remediation": "Fix it",
        },
    }


def test_run_fires_finding(tmp_path: Path, mock_context: Any) -> None:
    """Rule that matches insecure config should produce a Finding."""
    from mantou.engine.loader import load
    from mantou.engine.runner import FinderRegistry, run_all

    rules_dir = _write_rule(tmp_path / "rules", _base_rule("CFG-TST-001"))
    rules = load(rules_dir)
    finders = FinderRegistry(mock_context)
    findings, failures = run_all(rules, mock_context, finders)

    assert len(findings) == 1
    assert findings[0].id == "CFG-TST-001"
    assert findings[0].severity == "critical"
    assert failures == []


def test_run_no_finding_on_secure(tmp_path: Path, mock_context_secure: Any) -> None:
    """Rule that expects 0.0.0.0 should not fire on secure config (127.0.0.1)."""
    from mantou.engine.loader import load
    from mantou.engine.runner import FinderRegistry, run_all

    rules_dir = _write_rule(tmp_path / "rules", _base_rule("CFG-TST-002"))
    rules = load(rules_dir)
    finders = FinderRegistry(mock_context_secure)
    findings, failures = run_all(rules, mock_context_secure, finders)

    assert len(findings) == 0


def test_run_partial_failure_on_missing_config(tmp_path: Path) -> None:
    """When config file is missing, rule should produce a PartialFailure not crash."""
    from mantou.discovery import OpenClawContext
    from mantou.engine.loader import load
    from mantou.engine.runner import FinderRegistry, run_all

    ctx = OpenClawContext(
        config_path=tmp_path / "nonexistent.json",
        openclaw_dir=tmp_path,
        workspace_dir=tmp_path,
        prompt_files=[],
        sessions_dir=None,
        logs_dir=None,
        credentials_dir=None,
        root_override=None,
        vm_user=None,
        os_probes_disabled=True,
    )
    rules_dir = _write_rule(tmp_path / "rules", _base_rule("CFG-TST-003"))
    rules = load(rules_dir)
    finders = FinderRegistry(ctx)
    findings, failures = run_all(rules, ctx, finders)

    assert len(findings) == 0
    assert len(failures) == 1
    assert failures[0].reason == "unreadable_file"


def test_run_always_true_advisory_fires(tmp_path: Path, mock_context: Any) -> None:
    """Advisory rule with always_true should fire regardless of config state."""
    from mantou.engine.loader import load
    from mantou.engine.runner import FinderRegistry, run_all

    rule = _base_rule(
        "ADV-TST-001",
        condition={"operator": "always_true"},
    )
    rule["finding"]["severity"] = "info"
    rules_dir = _write_rule(tmp_path / "rules", rule)
    rules = load(rules_dir)
    finders = FinderRegistry(mock_context)
    findings, failures = run_all(rules, mock_context, finders)

    assert len(findings) == 1
    assert findings[0].severity == "info"


def test_run_all_real_rules_insecure(mock_context: Any, rules_dir: Path) -> None:
    """Smoke test: loading and running bundled rules against insecure config."""
    from mantou.engine.loader import load
    from mantou.engine.runner import FinderRegistry, run_all

    rules = load(rules_dir)
    finders = FinderRegistry(mock_context)
    findings, _ = run_all(rules, mock_context, finders)

    # Insecure config should produce at least several findings
    assert len(findings) >= 3
    severities = {f.severity for f in findings}
    assert "critical" in severities


def test_run_all_real_rules_secure(mock_context_secure: Any, rules_dir: Path) -> None:
    """Smoke test: secure config should produce no critical or high findings."""
    from mantou.engine.loader import load
    from mantou.engine.runner import FinderRegistry, run_all

    rules = load(rules_dir)
    finders = FinderRegistry(mock_context_secure)
    findings, _ = run_all(rules, mock_context_secure, finders)

    critical_or_high = [f for f in findings if f.severity in ("critical", "high")]
    assert len(critical_or_high) == 0, (
        f"Expected no critical/high findings on secure config, got: "
        f"{[(f.id, f.severity, f.title) for f in critical_or_high]}"
    )
