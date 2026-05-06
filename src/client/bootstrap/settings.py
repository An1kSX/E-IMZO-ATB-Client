from __future__ import annotations

from dataclasses import dataclass
import json
import logging
from pathlib import Path

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class AppSettings:
    api_eimzo_url: str | None = None
    duplicate_key_filter_enabled: bool = False


class AppSettingsStore:
    def __init__(self, runtime_dir: Path) -> None:
        self._settings_path = runtime_dir / "settings.json"

    def load(self) -> AppSettings:
        if not self._settings_path.exists():
            return AppSettings()

        try:
            payload = json.loads(self._settings_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            LOGGER.warning("Could not read app settings from %s: %s", self._settings_path, error)
            return AppSettings()

        if not isinstance(payload, dict):
            LOGGER.warning("Ignoring invalid app settings payload in %s", self._settings_path)
            return AppSettings()

        api_eimzo_url = payload.get("api_eimzo_url")
        if api_eimzo_url is not None and not isinstance(api_eimzo_url, str):
            LOGGER.warning("Ignoring invalid api_eimzo_url value in %s", self._settings_path)
            api_eimzo_url = None

        duplicate_key_filter_enabled = payload.get("duplicate_key_filter_enabled", False)
        if not isinstance(duplicate_key_filter_enabled, bool):
            LOGGER.warning("Ignoring invalid duplicate_key_filter_enabled value in %s", self._settings_path)
            duplicate_key_filter_enabled = False

        return AppSettings(
            api_eimzo_url=api_eimzo_url,
            duplicate_key_filter_enabled=duplicate_key_filter_enabled,
        )

    def save(self, settings: AppSettings) -> None:
        self._settings_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "api_eimzo_url": settings.api_eimzo_url,
            "duplicate_key_filter_enabled": settings.duplicate_key_filter_enabled,
        }
        self._settings_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
