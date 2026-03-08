"""Condition evaluator — maps operator names to boolean logic."""

from __future__ import annotations

import re
import stat
from typing import Any


class EvaluatorError(Exception):
    pass


def evaluate(condition: Any, probe_result: Any) -> bool:
    """Evaluate a condition spec against a probe result. Returns True if condition fires."""
    from mantou.engine.loader import ConditionSpec

    if isinstance(condition, dict):
        operator = condition.get("operator", "")
        value = condition.get("value")
        conditions = condition.get("conditions")
        sub_condition = condition.get("condition")
    elif isinstance(condition, ConditionSpec):
        operator = condition.operator
        value = condition.value
        conditions = condition.conditions
        sub_condition = condition.condition
    else:
        raise EvaluatorError(f"Unexpected condition type: {type(condition)}")

    if operator == "equals":
        return _coerce(probe_result) == _coerce(value)

    if operator == "not_equals":
        # Missing probe values should not trigger inequality findings.
        if probe_result is None:
            return False
        return _coerce(probe_result) != _coerce(value)

    if operator == "in":
        if not isinstance(value, list):
            raise EvaluatorError(f"'in' operator requires a list, got {type(value)}")
        return _coerce(probe_result) in [_coerce(v) for v in value]

    if operator == "not_in":
        if not isinstance(value, list):
            raise EvaluatorError(f"'not_in' operator requires a list, got {type(value)}")
        return _coerce(probe_result) not in [_coerce(v) for v in value]

    if operator == "matched":
        return bool(probe_result)

    if operator == "exists":
        return probe_result is not None and probe_result is not False

    if operator == "contains":
        if probe_result is None:
            return False
        return str(value) in str(probe_result)

    if operator == "gt":
        try:
            return float(probe_result) > float(value)
        except (TypeError, ValueError):
            return False

    if operator == "lt":
        try:
            return float(probe_result) < float(value)
        except (TypeError, ValueError):
            return False

    if operator == "contains_any":
        if not isinstance(value, list):
            value = [value]
        pr_str = str(probe_result).lower() if probe_result else ""
        return any(str(v).lower() in pr_str for v in value)

    if operator == "string_length_lt":
        if probe_result is None:
            return True  # absent key treated as length 0
        try:
            return len(str(probe_result)) < int(value)
        except (TypeError, ValueError):
            return False

    if operator == "semver_lt":
        return _semver_lt(str(probe_result), str(value))

    if operator == "always_true":
        return True

    if operator == "world_readable":
        mode = _extract_mode(probe_result)
        if mode is None:
            return False
        return bool(mode & stat.S_IROTH)

    if operator == "world_writable":
        mode = _extract_mode(probe_result)
        if mode is None:
            return False
        return bool(mode & stat.S_IWOTH)

    if operator == "mode_not_in":
        mode = _extract_mode(probe_result)
        if mode is None:
            return False
        octal_str = oct(stat.S_IMODE(mode))
        if not isinstance(value, list):
            value = [value]
        return octal_str not in [str(v) for v in value]

    if operator == "owner_in":
        owner = _extract_owner(probe_result)
        if not isinstance(value, list):
            value = [value]
        return owner in value

    if operator == "owner_not_in":
        owner = _extract_owner(probe_result)
        if not isinstance(value, list):
            value = [value]
        return owner not in value

    if operator == "and":
        if not conditions:
            raise EvaluatorError("'and' operator requires 'conditions' list")
        return all(evaluate(c, probe_result) for c in conditions)

    if operator == "or":
        if not conditions:
            raise EvaluatorError("'or' operator requires 'conditions' list")
        return any(evaluate(c, probe_result) for c in conditions)

    if operator == "not":
        if sub_condition is None:
            raise EvaluatorError("'not' operator requires 'condition'")
        return not evaluate(sub_condition, probe_result)

    raise EvaluatorError(f"Unknown condition operator: {operator!r}")


def _coerce(value: Any) -> Any:
    """Coerce probe result and condition values consistently for comparison."""
    if isinstance(value, str):
        return value.strip()
    return value


def _extract_mode(probe_result: Any) -> int | None:
    if isinstance(probe_result, dict):
        return probe_result.get("mode")
    if isinstance(probe_result, int):
        return probe_result
    return None


def _extract_owner(probe_result: Any) -> str:
    if isinstance(probe_result, dict):
        return probe_result.get("owner", "")
    return str(probe_result)


def _semver_lt(version_str: str, threshold_str: str) -> bool:
    """Compare version strings like 'v20.1.0' < '20.0.0'."""

    def parse(s: str) -> tuple[int, ...]:
        s = s.lstrip("v")
        m = re.match(r"(\d+)\.(\d+)\.(\d+)", s)
        if m:
            return tuple(int(x) for x in m.groups())
        m2 = re.match(r"(\d+)\.(\d+)", s)
        if m2:
            return tuple(int(x) for x in m2.groups()) + (0,)
        try:
            return (int(s.lstrip("v").split(".")[0]), 0, 0)
        except ValueError:
            return (0, 0, 0)

    return parse(version_str) < parse(threshold_str)
