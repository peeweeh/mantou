"""Filesystem finder — path existence, glob, and stat/permission probes."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mantou.discovery import OpenClawContext
    from mantou.engine.loader import ProbeSpec, TargetSpec


def _expand(path_str: str, context: OpenClawContext) -> Path:
    """Expand ~ and resolve relative to context root if a root override is set."""
    p = Path(path_str).expanduser()
    if context.root_override and not p.is_absolute():
        p = context.root_override / p
    return p


def _stat_result(path: Path) -> dict[str, Any]:
    try:
        st = os.stat(path)
    except PermissionError as exc:
        from mantou.engine.runner import ProbeError

        raise ProbeError(rule_id="", reason="permission_denied", detail=str(exc)) from exc
    except FileNotFoundError as exc:
        from mantou.engine.runner import ProbeError

        raise ProbeError(rule_id="", reason="unreadable_file", detail=str(exc)) from exc

    owner = ""
    group = ""
    try:
        import pwd

        owner = pwd.getpwuid(st.st_uid).pw_name
    except (ImportError, KeyError):
        owner = str(st.st_uid)
    try:
        import grp

        group = grp.getgrgid(st.st_gid).gr_name
    except (ImportError, KeyError):
        group = str(st.st_gid)

    return {
        "mode": stat.S_IMODE(st.st_mode),
        "mode_octal": oct(stat.S_IMODE(st.st_mode)),
        "owner": owner,
        "group": group,
        "is_dir": stat.S_ISDIR(st.st_mode),
        "is_file": stat.S_ISREG(st.st_mode),
        "size": st.st_size,
        "mtime": st.st_mtime,
    }


def probe(target: TargetSpec, probe_spec: ProbeSpec, context: OpenClawContext) -> Any:
    from mantou.engine.runner import ProbeError

    probe_type = probe_spec.type
    raw_path = target.path or (target.paths[0] if target.paths else None)

    if probe_type in ("exists_any", "path_exists"):
        paths_to_check = target.paths or ([raw_path] if raw_path else [])
        for p_str in paths_to_check:
            if _expand(p_str, context).exists():
                return True
        return False

    if probe_type == "exists_all":
        paths_to_check = target.paths or ([raw_path] if raw_path else [])
        return all(_expand(p_str, context).exists() for p_str in paths_to_check)

    if probe_type == "stat":
        if not raw_path:
            raise ProbeError(
                rule_id="", reason="unreadable_file", detail="stat probe requires a 'path'"
            )
        expanded = _expand(raw_path, context)
        if not expanded.exists():
            return None
        return _stat_result(expanded)

    if probe_type == "permissions":
        if not raw_path:
            raise ProbeError(
                rule_id="", reason="unreadable_file", detail="permissions probe requires a 'path'"
            )
        expanded = _expand(raw_path, context)
        if not expanded.exists():
            return None
        st = _stat_result(expanded)
        return st["mode_octal"]

    if probe_type == "text_contains":
        if not raw_path:
            raise ProbeError(
                rule_id="", reason="unreadable_file", detail="text_contains requires a 'path'"
            )
        expanded = _expand(raw_path, context)
        keyword = probe_spec.keyword or (
            probe_spec.value if isinstance(probe_spec.value, str) else ""
        )
        if not expanded.exists():
            return False
        try:
            content = expanded.read_text(encoding="utf-8", errors="replace")
            return keyword.lower() in content.lower()
        except PermissionError as exc:
            raise ProbeError(rule_id="", reason="permission_denied", detail=str(exc)) from exc

    if probe_type == "text_contains_any":
        if not raw_path:
            raise ProbeError(
                rule_id="", reason="unreadable_file", detail="text_contains_any requires a 'path'"
            )
        expanded = _expand(raw_path, context)
        keywords = probe_spec.keywords or []
        if not expanded.exists():
            return False
        try:
            content = expanded.read_text(encoding="utf-8", errors="replace").lower()
            return any(kw.lower() in content for kw in keywords)
        except PermissionError as exc:
            raise ProbeError(rule_id="", reason="permission_denied", detail=str(exc)) from exc

    raise ProbeError(
        rule_id="",
        reason="unsupported_platform",
        detail=f"Filesystem finder does not support probe type: {probe_type!r}",
    )
