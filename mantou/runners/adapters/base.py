"""Base types for Phase 2 tool output adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TypedDict

from mantou.runners.tool_runner import RawToolResult


class ParsedToolFinding(TypedDict):
    raw_severity: str
    title: str
    detail: str
    remediation: str
    section: str
    evidence_excerpt: str


class AbstractAdapter(ABC):
    command_id: str

    @abstractmethod
    def parse(self, result: RawToolResult) -> list[ParsedToolFinding]:
        raise NotImplementedError
