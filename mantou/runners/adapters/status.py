"""Adapter for status commands (stub until output format is finalized)."""

from __future__ import annotations

from mantou.runners.adapters.base import AbstractAdapter, ParsedToolFinding
from mantou.runners.tool_runner import RawToolResult


class StatusAdapter(AbstractAdapter):
    command_id = "status"

    def parse(self, result: RawToolResult) -> list[ParsedToolFinding]:
        _ = result
        return []
