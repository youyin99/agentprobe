from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .errors import PolicyError


@dataclass(frozen=True)
class PathResolution:
    requested: str
    absolute: Path
    within_workspace: bool
    within_sandbox: bool
    relative_to_workspace: str | None
    link_component: bool


def _has_link_or_reparse_component(path: Path) -> bool:
    """Check existing components for symlinks or Windows reparse points."""

    current = path
    while True:
        try:
            info = os.lstat(current)
        except OSError:
            parent = current.parent
            if parent == current:
                return False
            current = parent
            continue
        if stat.S_ISLNK(info.st_mode):
            return True
        attributes = getattr(info, "st_file_attributes", 0)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if attributes & reparse_flag:
            return True
        if current.parent == current:
            return False
        current = current.parent


def resolve_path(raw: str, workspace: Path, sandbox: Path) -> PathResolution:
    if not isinstance(raw, str) or not raw.strip():
        raise PolicyError("path must be a non-empty string")
    if "\x00" in raw:
        raise PolicyError("path contains a null byte")
    if Path(raw).is_absolute():
        raise PolicyError("absolute paths are not allowed")
    if raw.startswith(("\\\\", "//")):
        raise PolicyError("UNC-style paths are not allowed")

    workspace = workspace.resolve()
    sandbox = sandbox.resolve()
    candidate = workspace / raw
    try:
        absolute = candidate.resolve()
        workspace_real = workspace.resolve()
        sandbox_real = sandbox.resolve()
    except OSError as exc:
        raise PolicyError(f"path could not be resolved: {exc}") from exc

    within_workspace = _is_within(workspace_real, absolute)
    within_sandbox = _is_within(sandbox_real, absolute)
    relative = None
    if within_workspace:
        relative = absolute.relative_to(workspace_real).as_posix()
    link_component = _has_link_or_reparse_component(candidate)
    return PathResolution(
        requested=raw,
        absolute=absolute,
        within_workspace=within_workspace,
        within_sandbox=within_sandbox,
        relative_to_workspace=relative,
        link_component=link_component,
    )


def _is_within(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def has_parent_segments(raw: str) -> bool:
    return ".." in Path(raw.replace("\\", "/")).parts
