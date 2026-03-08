"""Tests for mantou.engine.loader."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mantou.engine.loader import RuleLoadError, load


def _write_rules(tmp_path: Path, filename: str, rules: list) -> Path:
    f = tmp_path / filename
    f.write_text(json.dumps(rules))
    return tmp_path


def _minimal_rule(rule_id: str = "CFG-001") -> dict:
    return {
        "id": rule_id,
        "enabled": True,
        "description": "Test rule",
        "tags": [],
        "target": {"type": "json", "path": "$.gateway.bind"},
        "probe": {"type": "value"},
        "condition": {"operator": "equals", "value": "0.0.0.0"},
        "finding": {
            "severity": "critical",
            "category": "config",
            "title": "Test",
            "detail": "Test detail",
            "remediation": "Fix it",
        },
    }


def test_load_valid_rules(tmp_path: Path) -> None:
    _write_rules(tmp_path, "test.json", [_minimal_rule("CFG-001"), _minimal_rule("CFG-002")])
    rules = load(tmp_path)
    assert len(rules) == 2
    assert rules[0].id == "CFG-001"
    assert rules[1].id == "CFG-002"


def test_load_empty_dir(tmp_path: Path) -> None:
    rules = load(tmp_path)
    assert rules == []


def test_load_skips_disabled(tmp_path: Path) -> None:
    rule = _minimal_rule("CFG-001")
    rule["enabled"] = False
    _write_rules(tmp_path, "test.json", [rule])
    rules = load(tmp_path)
    assert rules == []


def test_load_raises_on_duplicate_ids(tmp_path: Path) -> None:
    _write_rules(tmp_path, "test.json", [_minimal_rule("CFG-001"), _minimal_rule("CFG-001")])
    with pytest.raises(RuleLoadError, match="Duplicate rule ID"):
        load(tmp_path)


def test_load_raises_on_unknown_target_type(tmp_path: Path) -> None:
    rule = _minimal_rule()
    rule["target"]["type"] = "banana"
    _write_rules(tmp_path, "test.json", [rule])
    with pytest.raises(RuleLoadError):
        load(tmp_path)


def test_load_raises_on_unknown_probe_type(tmp_path: Path) -> None:
    rule = _minimal_rule()
    rule["probe"]["type"] = "not_a_probe"
    _write_rules(tmp_path, "test.json", [rule])
    with pytest.raises(RuleLoadError):
        load(tmp_path)


def test_load_sorts_by_id(tmp_path: Path) -> None:
    _write_rules(tmp_path, "test.json", [_minimal_rule("CFG-010"), _minimal_rule("CFG-002")])
    rules = load(tmp_path)
    assert [r.id for r in rules] == ["CFG-002", "CFG-010"]


def test_load_real_rules(rules_dir: Path) -> None:
    """Smoke test: bundled rule files can be loaded without errors."""
    rules = load(rules_dir)
    assert len(rules) > 20
    ids = [r.id for r in rules]
    assert "CFG-001" in ids
    assert "ADV-001" in ids
    assert "TOOL-001" in ids
