from __future__ import annotations

import os
from pathlib import Path
import sys


def resolve_app_icon_path() -> Path | None:
    configured_path = os.getenv("APP_ICON_PATH")
    if configured_path:
        candidate = Path(configured_path).expanduser()
        if candidate.exists() and candidate.is_file():
            return candidate

    for candidate in _candidate_paths():
        if candidate.exists() and candidate.is_file():
            return candidate

    return None


def _candidate_paths() -> list[Path]:
    candidates: list[Path] = []

    if getattr(sys, "frozen", False):
        executable_dir = Path(sys.executable).resolve().parent
        candidates.append(executable_dir / "icon.ico")

    candidates.append(Path.cwd() / "icon.ico")
    candidates.append(Path(__file__).resolve().parents[3] / "icon.ico")
    return _deduplicate(candidates)


def _deduplicate(paths: list[Path]) -> list[Path]:
    unique_paths: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        unique_paths.append(path)
    return unique_paths
