from __future__ import annotations

import os
from pathlib import Path
import sys


def load_dotenv() -> None:
    env_file = _resolve_env_file()
    if env_file is None:
        return

    for raw_line in env_file.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("export "):
            line = line[len("export ") :].strip()

        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        if not key or key in os.environ:
            continue

        os.environ[key] = _normalize_value(value.strip())


def _resolve_env_file() -> Path | None:
    configured_path = os.getenv("APP_ENV_FILE")
    if configured_path:
        candidate = Path(configured_path).expanduser()
        if candidate.exists():
            return candidate
        return None

    for candidate in _candidate_paths():
        if candidate.exists():
            return candidate

    return None


def _candidate_paths() -> list[Path]:
    candidates: list[Path] = [Path.cwd() / ".env"]

    if getattr(sys, "frozen", False):
        candidates.append(Path(sys.executable).resolve().parent / ".env")
    else:
        candidates.append(Path(__file__).resolve().parents[3] / ".env")

    unique_candidates: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        unique_candidates.append(candidate)

    return unique_candidates


def _normalize_value(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value
