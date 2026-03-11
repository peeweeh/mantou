"""Tests for mantou.finders.config."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest


def _make_context(config_path: Path, tmp_path: Path) -> Any:
    from mantou.discovery import OpenClawContext

    return OpenClawContext(
        config_path=config_path,
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


def _make_target(json_path: str) -> Any:
    from mantou.engine.loader import TargetSpec

    return TargetSpec(type="json", path=json_path)


def _make_probe(probe_type: str, **kwargs: Any) -> Any:
    from mantou.engine.loader import ProbeSpec

    return ProbeSpec(type=probe_type, **kwargs)


def test_probe_returns_value(insecure_config: Path, tmp_path: Path) -> None:
    from mantou.finders.config import probe

    ctx = _make_context(insecure_config, tmp_path)
    result = probe(_make_target("$.gateway.bind"), _make_probe("value"), ctx)
    assert result == "0.0.0.0"


def test_probe_returns_none_for_missing_key(insecure_config: Path, tmp_path: Path) -> None:
    from mantou.finders.config import probe

    ctx = _make_context(insecure_config, tmp_path)
    result = probe(_make_target("$.nonexistent.key"), _make_probe("value"), ctx)
    assert result is None


def test_probe_key_absent_or_empty_absent(insecure_config: Path, tmp_path: Path) -> None:
    """Missing key => key_absent_or_empty returns True."""
    from mantou.finders.config import probe

    ctx = _make_context(insecure_config, tmp_path)
    result = probe(_make_target("$.tools.shell.denylist"), _make_probe("key_absent_or_empty"), ctx)
    assert result is True


def test_probe_key_absent_or_empty_empty_list(tmp_path: Path) -> None:
    """Empty list => key_absent_or_empty returns True."""
    from mantou.finders.config import probe

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(json.dumps({"tools": {"shell": {"denylist": []}}}))
    ctx = _make_context(cfg, tmp_path)
    result = probe(_make_target("$.tools.shell.denylist"), _make_probe("key_absent_or_empty"), ctx)
    assert result is True


def test_probe_key_absent_or_empty_has_value(tmp_path: Path) -> None:
    """Non-empty list => key_absent_or_empty returns False."""
    from mantou.finders.config import probe

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(json.dumps({"tools": {"shell": {"denylist": ["rm -rf"]}}}))
    ctx = _make_context(cfg, tmp_path)
    result = probe(_make_target("$.tools.shell.denylist"), _make_probe("key_absent_or_empty"), ctx)
    assert result is False


def test_probe_contains_value_root(insecure_config: Path, tmp_path: Path) -> None:
    """insecure config has allowRead=['/'] — contains_value returns True."""
    from mantou.finders.config import probe

    ctx = _make_context(insecure_config, tmp_path)
    result = probe(
        _make_target("$.tools.filesystem.allowRead"),
        _make_probe("contains_value", value="/"),
        ctx,
    )
    assert result is True


def test_probe_contains_value_no_root(secure_config: Path, tmp_path: Path) -> None:
    """secure config does not have '/' in allowRead — contains_value returns False."""
    from mantou.finders.config import probe

    ctx = _make_context(secure_config, tmp_path)
    result = probe(
        _make_target("$.tools.filesystem.allowRead"),
        _make_probe("contains_value", value="/"),
        ctx,
    )
    assert result is False


def test_probe_key_absent_or_missing_paths_absent(insecure_config: Path, tmp_path: Path) -> None:
    """deny key absent => all required paths are missing => True."""
    from mantou.finders.config import probe

    ctx = _make_context(insecure_config, tmp_path)
    result = probe(
        _make_target("$.tools.filesystem.deny"),
        _make_probe("key_absent_or_missing_paths", paths=["~/.ssh", "~/.aws"]),
        ctx,
    )
    assert result is True


def test_probe_key_absent_or_missing_paths_present(secure_config: Path, tmp_path: Path) -> None:
    """secure config has all required paths => False."""
    from mantou.finders.config import probe

    ctx = _make_context(secure_config, tmp_path)
    result = probe(
        _make_target("$.tools.filesystem.deny"),
        _make_probe("key_absent_or_missing_paths", paths=["~/.ssh", "~/.aws"]),
        ctx,
    )
    assert result is False


def test_probe_raises_on_missing_file(tmp_path: Path) -> None:
    from mantou.engine.runner import ProbeError
    from mantou.finders.config import probe

    ctx = _make_context(tmp_path / "nonexistent.json", tmp_path)
    with pytest.raises(ProbeError):
        probe(_make_target("$.gateway.bind"), _make_probe("value"), ctx)


def test_probe_raises_on_malformed_json(tmp_path: Path) -> None:
    from mantou.engine.runner import ProbeError
    from mantou.finders.config import probe

    cfg = tmp_path / "openclaw.json"
    cfg.write_text("not json {{{")
    ctx = _make_context(cfg, tmp_path)
    with pytest.raises(ProbeError):
        probe(_make_target("$.gateway.bind"), _make_probe("value"), ctx)


def test_probe_loopback_with_empty_trusted_proxies_true(tmp_path: Path) -> None:
    from mantou.finders.config import probe

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(json.dumps({"gateway": {"bind": "127.0.0.1"}}))
    ctx = _make_context(cfg, tmp_path)
    result = probe(
        _make_target("$"),
        _make_probe("loopback_with_empty_trusted_proxies"),
        ctx,
    )
    assert result is True


def test_probe_loopback_with_empty_trusted_proxies_false(tmp_path: Path) -> None:
    from mantou.finders.config import probe

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(
        json.dumps(
            {
                "gateway": {
                    "bind": "127.0.0.1",
                    "trustedProxies": ["10.0.0.1"],
                }
            }
        )
    )
    ctx = _make_context(cfg, tmp_path)
    result = probe(
        _make_target("$"),
        _make_probe("loopback_with_empty_trusted_proxies"),
        ctx,
    )
    assert result is False


def test_probe_small_models_require_sandbox_all_true(tmp_path: Path) -> None:
    from mantou.finders.config import probe

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(
        json.dumps(
            {
                "agents": {
                    "defaults": {"sandbox": {"mode": "off"}},
                    "list": [{"id": "cheap", "model": "ollama/qwen3.5:9b"}],
                }
            }
        )
    )
    ctx = _make_context(cfg, tmp_path)
    result = probe(_make_target("$"), _make_probe("small_models_require_sandbox_all"), ctx)
    assert result is True


def test_probe_small_models_require_sandbox_all_false(tmp_path: Path) -> None:
    from mantou.finders.config import probe

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(
        json.dumps(
            {
                "agents": {
                    "defaults": {
                        "sandbox": {"mode": "all"},
                        "tools": {"deny": ["group:web", "browser"]},
                    },
                    "list": [
                        {
                            "id": "cheap",
                            "model": "ollama/qwen3.5:9b",
                            "tools": {"allow": ["read", "write"]},
                        }
                    ],
                }
            }
        )
    )
    ctx = _make_context(cfg, tmp_path)
    result = probe(_make_target("$"), _make_probe("small_models_require_sandbox_all"), ctx)
    assert result is False


def test_probe_open_groups_with_runtime_or_fs_true(tmp_path: Path) -> None:
    from mantou.finders.config import probe

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(
        json.dumps(
            {
                "channels": {"discord": {"groupPolicy": "open"}},
                "agents": {
                    "defaults": {"sandbox": {"mode": "off"}},
                    "list": [{"id": "main", "tools": {"allow": ["exec", "read"]}}],
                },
            }
        )
    )
    ctx = _make_context(cfg, tmp_path)
    result = probe(_make_target("$"), _make_probe("open_groups_with_runtime_or_fs"), ctx)
    assert result is True


def test_probe_open_groups_with_runtime_or_fs_false(tmp_path: Path) -> None:
    from mantou.finders.config import probe

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(
        json.dumps(
            {
                "channels": {"discord": {"groupPolicy": "allowlist"}},
                "agents": {
                    "defaults": {"sandbox": {"mode": "all"}},
                    "list": [{"id": "main", "tools": {"allow": ["read"]}}],
                },
            }
        )
    )
    ctx = _make_context(cfg, tmp_path)
    result = probe(_make_target("$"), _make_probe("open_groups_with_runtime_or_fs"), ctx)
    assert result is False


def test_probe_open_groups_with_elevated_true(tmp_path: Path) -> None:
    from mantou.finders.config import probe

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(
        json.dumps(
            {
                "channels": {"discord": {"groupPolicy": "open"}},
                "tools": {"elevated": True},
            }
        )
    )
    ctx = _make_context(cfg, tmp_path)
    result = probe(_make_target("$"), _make_probe("open_groups_with_elevated"), ctx)
    assert result is True


def test_probe_interpreter_safebins_without_profiles_true(tmp_path: Path) -> None:
    from mantou.finders.config import probe

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(
        json.dumps(
            {
                "agents": {
                    "list": [
                        {
                            "id": "a",
                            "tools": {"exec": {"safeBins": ["python3", "grep"]}},
                        }
                    ]
                }
            }
        )
    )
    ctx = _make_context(cfg, tmp_path)
    result = probe(
        _make_target("$"),
        _make_probe("interpreter_safebins_without_profiles"),
        ctx,
    )
    assert result is True


def test_probe_interpreter_safebins_without_profiles_false(tmp_path: Path) -> None:
    from mantou.finders.config import probe

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(
        json.dumps(
            {
                "agents": {
                    "list": [
                        {
                            "id": "a",
                            "tools": {
                                "exec": {
                                    "safeBins": ["python3", "grep"],
                                    "safeBinProfiles": {"python3": {"allow": []}},
                                }
                            },
                        }
                    ]
                }
            }
        )
    )
    ctx = _make_context(cfg, tmp_path)
    result = probe(
        _make_target("$"),
        _make_probe("interpreter_safebins_without_profiles"),
        ctx,
    )
    assert result is False


def test_probe_agent_shell_safebins_present_true(tmp_path: Path) -> None:
    from mantou.finders.config import probe

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(
        json.dumps(
            {"agents": {"list": [{"id": "a", "tools": {"exec": {"safeBins": ["bash", "grep"]}}}]}}
        )
    )
    ctx = _make_context(cfg, tmp_path)
    result = probe(_make_target("$"), _make_probe("agent_shell_safebins_present"), ctx)
    assert result is True


def test_probe_agent_automation_safebins_present_true(tmp_path: Path) -> None:
    from mantou.finders.config import probe

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(
        json.dumps(
            {
                "agents": {
                    "list": [
                        {
                            "id": "a",
                            "tools": {"exec": {"safeBins": ["osascript", "curl"]}},
                        }
                    ]
                }
            }
        )
    )
    ctx = _make_context(cfg, tmp_path)
    result = probe(_make_target("$"), _make_probe("agent_automation_safebins_present"), ctx)
    assert result is True


def test_probe_agent_package_manager_safebins_present_true(tmp_path: Path) -> None:
    from mantou.finders.config import probe

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(
        json.dumps(
            {"agents": {"list": [{"id": "a", "tools": {"exec": {"safeBins": ["pip3", "jq"]}}}]}}
        )
    )
    ctx = _make_context(cfg, tmp_path)
    result = probe(
        _make_target("$"),
        _make_probe("agent_package_manager_safebins_present"),
        ctx,
    )
    assert result is True


def test_probe_agent_infra_cli_safebins_present_true(tmp_path: Path) -> None:
    from mantou.finders.config import probe

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(
        json.dumps(
            {"agents": {"list": [{"id": "a", "tools": {"exec": {"safeBins": ["docker", "jq"]}}}]}}
        )
    )
    ctx = _make_context(cfg, tmp_path)
    result = probe(_make_target("$"), _make_probe("agent_infra_cli_safebins_present"), ctx)
    assert result is True


def test_probe_agent_broad_workspace_without_workspace_only_true(tmp_path: Path) -> None:
    from mantou.finders.config import probe

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(
        json.dumps(
            {
                "agents": {
                    "list": [
                        {
                            "id": "a",
                            "workspace": "/Users/test/dev",
                            "tools": {"fs": {"workspaceOnly": False}},
                        }
                    ]
                }
            }
        )
    )
    ctx = _make_context(cfg, tmp_path)
    result = probe(
        _make_target("$"),
        _make_probe("agent_broad_workspace_without_workspace_only"),
        ctx,
    )
    assert result is True


def test_probe_agent_broad_workspace_without_workspace_only_false_for_isolated_path(
    tmp_path: Path,
) -> None:
    from mantou.finders.config import probe

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(
        json.dumps(
            {
                "agents": {
                    "list": [
                        {
                            "id": "a",
                            "workspace": "~/.openclaw/workspace/agents/a",
                            "tools": {"fs": {"workspaceOnly": False}},
                        }
                    ]
                }
            }
        )
    )
    ctx = _make_context(cfg, tmp_path)
    result = probe(
        _make_target("$"),
        _make_probe("agent_broad_workspace_without_workspace_only"),
        ctx,
    )
    assert result is False


def test_probe_agent_high_power_tools_without_exec_ask_true(tmp_path: Path) -> None:
    from mantou.finders.config import probe

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(
        json.dumps(
            {
                "agents": {
                    "list": [
                        {
                            "id": "a",
                            "tools": {
                                "allow": ["sessions_spawn", "read"],
                                "exec": {"ask": "never"},
                            },
                        }
                    ]
                }
            }
        )
    )
    ctx = _make_context(cfg, tmp_path)
    result = probe(
        _make_target("$"),
        _make_probe("agent_high_power_tools_without_exec_ask"),
        ctx,
    )
    assert result is True


def test_probe_discord_open_thread_spawn_true(tmp_path: Path) -> None:
    from mantou.finders.config import probe

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(
        json.dumps(
            {
                "channels": {
                    "discord": {
                        "groupPolicy": "open",
                        "threadBindings": {"spawnSubagentSessions": True},
                    }
                }
            }
        )
    )
    ctx = _make_context(cfg, tmp_path)
    result = probe(_make_target("$"), _make_probe("discord_open_thread_spawn"), ctx)
    assert result is True


def test_probe_hardcoded_secret_value_skips_env_refs(tmp_path: Path) -> None:
    from mantou.finders.config import probe

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(
        json.dumps(
            {"models": {"providers": {"trendmicro-aiendpoint": {"apiKey": "$TRENDMICRO_API_KEY"}}}}
        )
    )
    ctx = _make_context(cfg, tmp_path)
    result = probe(
        _make_target("$.models.providers.*.apiKey"),
        _make_probe("hardcoded_secret_value"),
        ctx,
    )
    assert result is False


def test_probe_hardcoded_secret_value_true_for_literal(tmp_path: Path) -> None:
    from mantou.finders.config import probe

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(
        json.dumps(
            {"models": {"providers": {"trendmicro-aiendpoint": {"apiKey": "eyJhbGci.fake.jwt"}}}}
        )
    )
    ctx = _make_context(cfg, tmp_path)
    result = probe(
        _make_target("$.models.providers.*.apiKey"),
        _make_probe("hardcoded_secret_value"),
        ctx,
    )
    assert result is True
