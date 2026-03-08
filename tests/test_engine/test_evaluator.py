"""Tests for mantou.engine.evaluator."""

from __future__ import annotations

import pytest

from mantou.engine.evaluator import EvaluatorError, evaluate


def cond(operator: str, value=None, conditions=None, condition=None) -> dict:
    d: dict = {"operator": operator}
    if value is not None:
        d["value"] = value
    if conditions is not None:
        d["conditions"] = conditions
    if condition is not None:
        d["condition"] = condition
    return d


# ── Basic scalar operators ────────────────────────────────────────────────────


def test_equals_match() -> None:
    assert evaluate(cond("equals", "0.0.0.0"), "0.0.0.0") is True


def test_equals_no_match() -> None:
    assert evaluate(cond("equals", "0.0.0.0"), "127.0.0.1") is False


def test_not_equals() -> None:
    assert evaluate(cond("not_equals", "open"), "allowlist") is True
    assert evaluate(cond("not_equals", "open"), "open") is False


def test_in_operator() -> None:
    assert evaluate(cond("in", ["0.0.0.0", "::"]), "0.0.0.0") is True
    assert evaluate(cond("in", ["0.0.0.0", "::"]), "127.0.0.1") is False


def test_not_in_operator() -> None:
    assert evaluate(cond("not_in", ["127.0.0.1", "localhost"]), "0.0.0.0") is True
    assert evaluate(cond("not_in", ["127.0.0.1", "localhost"]), "127.0.0.1") is False


def test_exists_truthy() -> None:
    assert evaluate(cond("exists"), "something") is True
    assert evaluate(cond("exists"), None) is False


def test_gt() -> None:
    assert evaluate(cond("gt", 1.0), 1.5) is True
    assert evaluate(cond("gt", 1.0), 0.5) is False


def test_lt() -> None:
    assert evaluate(cond("lt", 30), 5) is True
    assert evaluate(cond("lt", 30), 30) is False


# ── String/pattern operators ──────────────────────────────────────────────────


def test_matched_true() -> None:
    assert evaluate(cond("matched"), "some match result") is True


def test_matched_false_empty() -> None:
    assert evaluate(cond("matched"), "") is False
    assert evaluate(cond("matched"), None) is False


def test_contains() -> None:
    assert evaluate(cond("contains", "opus"), "claude-4-opus") is True
    assert evaluate(cond("contains", "opus"), "claude-haiku") is False


def test_contains_any() -> None:
    assert evaluate(cond("contains_any", ["opus", "gpt-4"]), "claude-4-opus") is True
    assert evaluate(cond("contains_any", ["opus", "gpt-4"]), "claude-haiku") is False


def test_string_length_lt_absent_key() -> None:
    """None (absent key) counts as length 0 — should fire."""
    assert evaluate(cond("string_length_lt", 32), None) is True


def test_string_length_lt_below_threshold() -> None:
    assert evaluate(cond("string_length_lt", 32), "tooshort") is True


def test_string_length_lt_above_threshold() -> None:
    token = "a" * 64
    assert evaluate(cond("string_length_lt", 32), token) is False


# ── Semantic version ──────────────────────────────────────────────────────────


def test_semver_lt_fires() -> None:
    assert evaluate(cond("semver_lt", "20.0.0"), "v16.14.2") is True


def test_semver_lt_no_fire() -> None:
    assert evaluate(cond("semver_lt", "20.0.0"), "v20.1.0") is False


# ── Permission operators ──────────────────────────────────────────────────────


def test_world_readable_fires() -> None:

    mode = 0o644  # owner rw, group r, world r
    assert evaluate(cond("world_readable"), {"mode": mode}) is True


def test_world_readable_no_fire() -> None:
    mode = 0o600  # owner rw only
    assert evaluate(cond("world_readable"), {"mode": mode}) is False


def test_world_writable_fires() -> None:
    mode = 0o777
    assert evaluate(cond("world_writable"), {"mode": mode}) is True


# ── Boolean operators ─────────────────────────────────────────────────────────


def test_always_true() -> None:
    assert evaluate(cond("always_true"), None) is True
    assert evaluate(cond("always_true"), "anything") is True


def test_and_all_match() -> None:
    c = cond("and", conditions=[cond("equals", "open"), cond("exists")])
    assert evaluate(c, "open") is True


def test_and_partial_match() -> None:
    c = cond("and", conditions=[cond("equals", "closed"), cond("exists")])
    assert evaluate(c, "open") is False


def test_or_one_match() -> None:
    c = cond("or", conditions=[cond("equals", "open"), cond("equals", "public")])
    assert evaluate(c, "open") is True
    assert evaluate(c, "none") is False


def test_not_inverts() -> None:
    c = cond("not", condition=cond("equals", "127.0.0.1"))
    assert evaluate(c, "0.0.0.0") is True
    assert evaluate(c, "127.0.0.1") is False


def test_unknown_operator_raises() -> None:
    with pytest.raises(EvaluatorError, match="Unknown condition operator"):
        evaluate(cond("banana"), "value")
