"""Paths shown to API clients: relative to the project, never the server's
absolute file system layout (which reveals user names and directories)."""
from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def public_path(path: str | Path) -> str:
    """Project-relative path with forward slashes; just the file name if the
    path lies outside the project."""
    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return resolved.name


def public_message(text: str | None) -> str | None:
    """An error message with the project's absolute location removed."""
    if not text:
        return text
    for root in {str(PROJECT_ROOT), PROJECT_ROOT.as_posix()}:
        text = text.replace(root + "\\", "").replace(root + "/", "").replace(root, "")
    return text
