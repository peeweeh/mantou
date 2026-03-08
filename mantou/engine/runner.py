"""Rule runner — executes each rule's probe + condition and emits findings."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from mantou.engine.evaluator import evaluate
from mantou.engine.loader import Rule
from mantou.schema import Finding, PartialFailure

if TYPE_CHECKING:
    from mantou.discovery import OpenClawContext


class ProbeError(Exception):
    def __init__(
        self,
        rule_id: str,
        reason: str,
        detail: str,
    ) -> None:
        super().__init__(detail)
        self.rule_id = rule_id
        self.reason = reason
        self.detail = detail


def run_all(
    rules: list[Rule],
    context: OpenClawContext,
    finders: FinderRegistry,
) -> tuple[list[Finding], list[PartialFailure]]:
    """Run all rules against context. Returns (findings, partial_failures)."""
    findings: list[Finding] = []
    failures: list[PartialFailure] = []

    for rule in rules:
        try:
            rule_findings = _run_rule(rule, context, finders)
            findings.extend(rule_findings)
        except ProbeError as exc:
            failures.append(
                PartialFailure(
                    rule_id=exc.rule_id,
                    reason=exc.reason,  # type: ignore[arg-type]
                    detail=exc.detail,
                )
            )
        except Exception as exc:  # noqa: BLE001
            failures.append(
                PartialFailure(
                    rule_id=rule.id,
                    reason="unreadable_file",
                    detail=f"Unexpected error: {exc}",
                )
            )

    return findings, failures


def _run_rule(
    rule: Rule,
    context: OpenClawContext,
    finders: FinderRegistry,
) -> list[Finding]:
    """Run a single rule. Returns list of findings (0 or more, >1 for foreach_json)."""
    if rule.target.type == "foreach_json":
        return _run_foreach_rule(rule, context, finders)

    probe_result = finders.probe(rule, context)
    fired = evaluate(rule.condition, probe_result)
    if not fired:
        return []

    resource = _build_resource(rule, context, probe_result)
    return [_build_finding(rule, resource, probe_result)]


def _run_foreach_rule(
    rule: Rule,
    context: OpenClawContext,
    finders: FinderRegistry,
) -> list[Finding]:
    """Handle foreach_json rules — iterate array items, emit one finding per match."""
    items = finders.probe(rule, context)

    if not isinstance(items, list):
        raise ProbeError(
            rule_id=rule.id,
            reason="malformed_json",
            detail=f"foreach_json path did not resolve to a list: {type(items)}",
        )

    findings: list[Finding] = []
    for item in items:
        try:
            fired = evaluate(rule.condition, item)
        except Exception as exc:  # noqa: BLE001
            raise ProbeError(
                rule_id=rule.id,
                reason="malformed_json",
                detail=f"Error evaluating condition on item {item!r}: {exc}",
            ) from exc

        if fired:
            resource = _build_resource_template(rule, item)
            findings.append(_build_finding(rule, resource, item))

    return findings


def _build_resource(rule: Rule, context: OpenClawContext, probe_result: Any) -> str:
    if rule.finding.resource:
        return rule.finding.resource
    if rule.finding.resource_template:
        return _build_resource_template(rule, probe_result)
    target = rule.target
    if target.type == "json" and context.config_path:
        return f"file://{context.config_path}"
    if target.type in ("path", "fs_perm") and target.path:
        return f"file://{target.path}"
    if target.type == "command" and target.command_id:
        return f"command://{target.command_id}"
    if target.type == "text" and target.path:
        return f"file://{target.path}"
    return f"openclaw://rule/{rule.id}"


def _build_resource_template(rule: Rule, item: Any) -> str:
    template = rule.resource_template or rule.finding.resource_template or "openclaw://item/{id}"
    if isinstance(item, dict):
        try:
            return template.format(**item)
        except (KeyError, ValueError):
            return template
    return template


def _build_finding(rule: Rule, resource: str, evidence_value: Any) -> Finding:
    evidence_str = _safe_evidence(evidence_value)
    return Finding(
        id=rule.id,
        source="static",
        phase=1,
        severity=rule.finding.severity,  # type: ignore[arg-type]
        category=rule.finding.category,  # type: ignore[arg-type]
        resource=resource,
        title=rule.finding.title,
        detail=rule.finding.detail,
        evidence=evidence_str,
        remediation=rule.finding.remediation,
    )


def _safe_evidence(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        # Redact any key that looks like a credential
        _SENSITIVE = {"token", "secret", "password", "key", "api_key"}
        redacted = {
            k: "[REDACTED]" if any(s in k.lower() for s in _SENSITIVE) else v
            for k, v in value.items()
        }
        return str(redacted)
    return str(value)


class FinderRegistry:
    """Dispatches probe calls to the appropriate finder module."""

    def __init__(self, context: OpenClawContext) -> None:
        from mantou.finders import command, config, filesystem, text

        self._config = config
        self._filesystem = filesystem
        self._text = text
        self._command = command
        self._context = context

    def probe(self, rule: Rule, context: OpenClawContext) -> Any:
        target_type = rule.target.type

        if target_type == "json":
            return self._config.probe(rule.target, rule.probe, context)
        if target_type in ("path", "fs_perm"):
            return self._filesystem.probe(rule.target, rule.probe, context)
        if target_type == "text":
            return self._text.probe(rule.target, rule.probe, context)
        if target_type == "command":
            return self._command.probe(rule.target, rule.probe, context)
        if target_type == "foreach_json":
            return self._config.probe_foreach(rule.target, rule.probe, context)
        if target_type == "filesystem":
            return self._filesystem.probe(rule.target, rule.probe, context)

        raise ProbeError(
            rule_id=rule.id,
            reason="unsupported_platform",
            detail=f"No finder for target type: {target_type!r}",
        )
