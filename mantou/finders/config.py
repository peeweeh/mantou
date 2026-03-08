"""Config finder — reads openclaw.json and evaluates JSONPath expressions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mantou.discovery import OpenClawContext
    from mantou.engine.loader import ProbeSpec, TargetSpec


class ConfigProbeError(Exception):
    def __init__(
        self, rule_id: str = "", reason: str = "unreadable_file", detail: str = ""
    ) -> None:
        super().__init__(detail)
        self.rule_id = rule_id
        self.reason = reason
        self.detail = detail


def _resolve_config_path(target: TargetSpec, context: OpenClawContext) -> Path:
    if target.file and target.file != "openclaw.json":
        return Path(target.file).expanduser()
    if context.config_path:
        return context.config_path
    raise ConfigProbeError(
        reason="unreadable_file",
        detail="openclaw.json not found — run mantou scan --config <path>",
    )


def _load_json(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except PermissionError as exc:
        raise ConfigProbeError(reason="permission_denied", detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise ConfigProbeError(reason="unreadable_file", detail=str(exc)) from exc

    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigProbeError(reason="malformed_json", detail=str(exc)) from exc


def _jsonpath_query(data: Any, expression: str) -> Any:
    from jsonpath_ng.ext import parse as jp_parse  # type: ignore[import]

    try:
        matches = jp_parse(expression).find(data)
    except Exception as exc:
        raise ConfigProbeError(reason="malformed_json", detail=f"JSONPath error: {exc}") from exc

    if not matches:
        return None
    if len(matches) == 1:
        return matches[0].value
    return [m.value for m in matches]


def probe(target: TargetSpec, probe_spec: ProbeSpec, context: OpenClawContext) -> Any:
    """Probe a JSON config file at a JSONPath expression."""
    from mantou.engine.runner import ProbeError

    try:
        config_path = _resolve_config_path(target, context)
        data = _load_json(config_path)
        json_path = target.path or getattr(probe_spec, "json_path", None)
        if not json_path:
            return data
        raw = _jsonpath_query(data, json_path)
        return _apply_probe_transform(probe_spec, raw)
    except ConfigProbeError as exc:
        raise ProbeError(
            rule_id="",
            reason=exc.reason,
            detail=exc.detail,
        ) from exc


def _apply_probe_transform(probe_spec: ProbeSpec, raw: Any) -> Any:
    """Apply specialized probe type transforms that return a boolean directly."""
    ptype = probe_spec.type

    if ptype == "key_absent_or_empty":
        if raw is None:
            return True
        if isinstance(raw, (list, dict, str)) and len(raw) == 0:
            return True
        return False

    if ptype == "contains_value":
        check = probe_spec.value
        if not isinstance(raw, list):
            return False
        # Check direct membership or if any list element contains the value as a prefix
        return check in raw or any(isinstance(item, str) and item == check for item in raw)

    if ptype == "key_absent_or_missing_paths":
        required: list[str] = probe_spec.paths or []
        if not required:
            return False
        if raw is None or not isinstance(raw, list):
            return True  # absent = all paths missing
        return any(p not in raw for p in required)

    return raw


def probe_foreach(target: TargetSpec, probe_spec: ProbeSpec, context: OpenClawContext) -> list[Any]:
    """For foreach_json rules — resolve the JSONPath and return the list."""
    from mantou.engine.runner import ProbeError

    try:
        config_path = _resolve_config_path(target, context)
        data = _load_json(config_path)
        json_path = target.path
        if not json_path:
            raise ConfigProbeError(
                reason="malformed_json", detail="foreach_json target requires 'path'"
            )
        result = _jsonpath_query(data, json_path)
        if result is None:
            return []
        if not isinstance(result, list):
            result = [result]
        return result
    except ConfigProbeError as exc:
        raise ProbeError(
            rule_id="",
            reason=exc.reason,
            detail=exc.detail,
        ) from exc
