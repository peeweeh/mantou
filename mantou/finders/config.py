"""Config finder — reads openclaw.json and evaluates JSONPath expressions."""

from __future__ import annotations

import json
import re
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

    if ptype == "loopback_with_empty_trusted_proxies":
        return _loopback_with_empty_trusted_proxies(raw)

    if ptype == "small_models_require_sandbox_all":
        return _small_models_require_sandbox_all(raw)

    if ptype == "open_groups_with_runtime_or_fs":
        return _open_groups_with_runtime_or_fs(raw)

    if ptype == "open_groups_with_elevated":
        return _open_groups_with_elevated(raw)

    if ptype == "interpreter_safebins_without_profiles":
        return _interpreter_safebins_without_profiles(raw)

    return raw


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _extract_sandbox_mode(config: dict[str, Any]) -> str:
    sandbox = _as_dict(config.get("sandbox"))
    mode = sandbox.get("mode")
    return str(mode).strip().lower() if mode is not None else ""


def _is_unsafe_sandbox(mode: str) -> bool:
    return mode != "all"


def _open_group_paths(config: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    channels = _as_dict(config.get("channels"))
    for channel_name, channel_cfg_raw in channels.items():
        channel_cfg = _as_dict(channel_cfg_raw)
        if str(channel_cfg.get("groupPolicy", "")).lower() == "open":
            paths.append(f"channels.{channel_name}.groupPolicy")

        accounts = _as_dict(channel_cfg.get("accounts"))
        for account_name, account_cfg_raw in accounts.items():
            account_cfg = _as_dict(account_cfg_raw)
            if str(account_cfg.get("groupPolicy", "")).lower() == "open":
                paths.append(f"channels.{channel_name}.accounts.{account_name}.groupPolicy")

    return paths


def _tool_is_denied(tool: str, denyset: set[str]) -> bool:
    if tool in denyset:
        return True
    if "group:web" in denyset and tool in {"web_search", "web_fetch", "browser"}:
        return True
    return False


def _web_tools_exposed(tools: dict[str, Any], default_tools: dict[str, Any]) -> bool:
    allow = _as_list(tools.get("allow")) or _as_list(default_tools.get("allow"))
    deny = _as_list(default_tools.get("deny")) + _as_list(tools.get("deny"))
    denyset = {str(x) for x in deny}
    for web_tool in ("web_search", "web_fetch", "browser"):
        if web_tool in allow and not _tool_is_denied(web_tool, denyset):
            return True
    return False


def _allows_runtime_or_fs(tools: dict[str, Any]) -> bool:
    allow = {str(x) for x in _as_list(tools.get("allow"))}
    risky = {"exec", "process", "read", "write", "edit", "apply_patch"}
    if bool(allow & risky):
        return True

    # Legacy style root tools still indicates runtime/fs capability when configured.
    if _as_dict(tools.get("shell")):
        return True
    if _as_dict(tools.get("filesystem")):
        return True

    if _as_dict(tools.get("exec")):
        return True
    if _as_dict(tools.get("fs")):
        return True

    return False


def _model_param_size_b(model: str) -> float | None:
    match = re.search(r"(\d+(?:\.\d+)?)\s*[bB]\b", model)
    if not match:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def _loopback_with_empty_trusted_proxies(raw: Any) -> bool:
    config = _as_dict(raw)
    gateway = _as_dict(config.get("gateway"))
    bind = str(gateway.get("bind", "")).strip().lower()
    if bind not in {"127.0.0.1", "::1", "localhost"}:
        return False
    trusted = gateway.get("trustedProxies")
    return not bool(_as_list(trusted))


def _small_models_require_sandbox_all(raw: Any) -> bool:
    config = _as_dict(raw)
    agents = _as_dict(config.get("agents"))
    defaults = _as_dict(agents.get("defaults"))
    default_tools = _as_dict(defaults.get("tools"))
    default_sandbox = _extract_sandbox_mode(defaults)

    for agent_raw in _as_list(agents.get("list")):
        agent = _as_dict(agent_raw)
        model = str(agent.get("model", ""))
        size_b = _model_param_size_b(model)
        if size_b is None or size_b > 300:
            continue

        sandbox = _extract_sandbox_mode(agent) or default_sandbox
        tools = _as_dict(agent.get("tools"))
        if _is_unsafe_sandbox(sandbox):
            return True
        if _web_tools_exposed(tools, default_tools):
            return True

    return False


def _open_groups_with_runtime_or_fs(raw: Any) -> bool:
    config = _as_dict(raw)
    if not _open_group_paths(config):
        return False

    agents = _as_dict(config.get("agents"))
    defaults = _as_dict(agents.get("defaults"))
    default_sandbox = _extract_sandbox_mode(defaults)
    default_tools = _as_dict(defaults.get("tools"))

    if _is_unsafe_sandbox(default_sandbox):
        if _allows_runtime_or_fs(default_tools):
            return True
        if _allows_runtime_or_fs(_as_dict(config.get("tools"))):
            return True

    for agent_raw in _as_list(agents.get("list")):
        agent = _as_dict(agent_raw)
        sandbox = _extract_sandbox_mode(agent) or default_sandbox
        tools = _as_dict(agent.get("tools"))
        if _is_unsafe_sandbox(sandbox) and _allows_runtime_or_fs(tools):
            return True

    return False


def _open_groups_with_elevated(raw: Any) -> bool:
    config = _as_dict(raw)
    if not _open_group_paths(config):
        return False

    root_tools = _as_dict(config.get("tools"))
    if bool(root_tools.get("elevated")):
        return True

    agents = _as_dict(config.get("agents"))
    defaults = _as_dict(agents.get("defaults"))
    default_tools = _as_dict(defaults.get("tools"))
    if bool(default_tools.get("elevated")):
        return True

    for agent_raw in _as_list(agents.get("list")):
        agent = _as_dict(agent_raw)
        tools = _as_dict(agent.get("tools"))
        if bool(tools.get("elevated")):
            return True

    return False


def _interpreter_safebins_without_profiles(raw: Any) -> bool:
    config = _as_dict(raw)
    agents = _as_dict(config.get("agents"))
    interpreter_bins = {
        "python",
        "python3",
        "pip",
        "pip3",
        "node",
        "npm",
        "npx",
        "ruby",
        "perl",
        "php",
        "bash",
        "sh",
        "zsh",
    }

    for agent_raw in _as_list(agents.get("list")):
        agent = _as_dict(agent_raw)
        tools = _as_dict(agent.get("tools"))
        exec_cfg = _as_dict(tools.get("exec"))
        safe_bins = {str(x).lower() for x in _as_list(exec_cfg.get("safeBins"))}
        if not safe_bins:
            continue
        profiles = _as_dict(exec_cfg.get("safeBinProfiles"))
        for bin_name in safe_bins & interpreter_bins:
            if bin_name not in profiles:
                return True

    return False


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
