"""Rule loader — reads and validates JSON rule files from a directory."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, field_validator


class RuleLoadError(Exception):
    pass


KNOWN_TARGET_TYPES = frozenset(
    ["json", "path", "fs_perm", "text", "command", "foreach_json", "filesystem"]
)
KNOWN_PROBE_TYPES = frozenset(
    [
        "value",
        "exists_any",
        "exists_all",
        "stat",
        "regex_any",
        "regex_all",
        "stdout",
        "key_absent",
        "path_exists",
        "text_contains",
        "text_contains_any",
        "key_absent_or_empty",
        "contains_value",
        "key_absent_or_missing_paths",
        "string_length",
        "permissions",
    ]
)


class TargetSpec(BaseModel):
    type: str
    file: str | None = None
    path: str | None = None
    command_id: str | None = None
    platform: list[str] | None = None
    paths: list[str] | None = None

    model_config = {"extra": "allow"}


class ProbeSpec(BaseModel):
    type: str
    key: str | None = None
    patterns: list[str] | None = None
    pattern: str | None = None
    value: Any = None
    keyword: str | None = None
    keywords: list[str] | None = None
    paths: list[str] | None = None
    threshold: int | None = None

    model_config = {"extra": "allow"}


class ConditionSpec(BaseModel):
    operator: str
    value: Any = None
    conditions: list[ConditionSpec] | None = None
    condition: ConditionSpec | None = None

    model_config = {"extra": "allow"}


class FindingTemplate(BaseModel):
    severity: str
    category: str
    title: str
    detail: str
    remediation: str
    resource: str | None = None
    resource_template: str | None = None

    model_config = {"extra": "allow"}


class Rule(BaseModel):
    id: str
    enabled: bool
    description: str
    tags: list[str] = []
    target: TargetSpec
    probe: ProbeSpec
    condition: ConditionSpec
    finding: FindingTemplate
    resource_template: str | None = None

    @field_validator("target")
    @classmethod
    def validate_target_type(cls, v: TargetSpec) -> TargetSpec:
        if v.type not in KNOWN_TARGET_TYPES:
            raise ValueError(f"Unknown target type: {v.type!r}")
        return v

    @field_validator("probe")
    @classmethod
    def validate_probe_type(cls, v: ProbeSpec) -> ProbeSpec:
        if v.type not in KNOWN_PROBE_TYPES:
            raise ValueError(f"Unknown probe type: {v.type!r}")
        return v


def load(rules_dir: Path) -> list[Rule]:
    """Load all enabled rules from *.json files in rules_dir, sorted by ID."""
    if not rules_dir.exists():
        return []

    all_rules: list[Rule] = []
    seen_ids: dict[str, Path] = {}
    errors: list[str] = []

    for rule_file in sorted(rules_dir.glob("*.json")):
        try:
            raw = json.loads(rule_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RuleLoadError(f"Malformed JSON in {rule_file}: {exc}") from exc

        if not isinstance(raw, list):
            raise RuleLoadError(f"{rule_file} must contain a JSON array of rules")

        for item in raw:
            if not isinstance(item, dict):
                errors.append(f"{rule_file}: rule item must be a dict, got {type(item)}")
                continue

            rule_id = item.get("id", "<unknown>")
            try:
                rule = Rule.model_validate(item)
            except Exception as exc:
                errors.append(f"{rule_file} rule {rule_id!r}: {exc}")
                continue

            if not rule.enabled:
                continue

            if rule.id in seen_ids:
                errors.append(
                    f"Duplicate rule ID {rule.id!r} in {rule_file} "
                    f"(first seen in {seen_ids[rule.id]})"
                )
                continue

            seen_ids[rule.id] = rule_file
            all_rules.append(rule)

    if errors:
        raise RuleLoadError("Rule load errors:\n" + "\n".join(f"  - {e}" for e in errors))

    return sorted(all_rules, key=lambda r: r.id)
