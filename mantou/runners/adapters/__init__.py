"""Adapter registry for Phase 2 command outputs."""

from __future__ import annotations

from mantou.runners.adapters.base import AbstractAdapter
from mantou.runners.adapters.doctor import DoctorAdapter
from mantou.runners.adapters.security_audit import SecurityAuditAdapter
from mantou.runners.adapters.status import StatusAdapter

ADAPTERS: dict[str, AbstractAdapter] = {
    "doctor": DoctorAdapter(),
    "security_audit": SecurityAuditAdapter(),
    "security_audit_deep": SecurityAuditAdapter(),
    "status": StatusAdapter(),
    "daemon_status": StatusAdapter(),
    "gateway_status": StatusAdapter(),
}


def get_adapter(command_id: str) -> AbstractAdapter:
    if command_id not in ADAPTERS:
        raise ValueError(f"No adapter for command_id={command_id!r}")
    return ADAPTERS[command_id]
