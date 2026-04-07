from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

_LOG_FILE_MAX_BYTES = 5 * 1024 * 1024
_LOG_FILE_BACKUP_COUNT = 50
_LOGGER = logging.getLogger(__name__)


class _ApplicationLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        is_application_log = record.name.startswith("client.")
        is_user_action = bool(getattr(record, "user_action", False))
        return is_application_log and (record.levelno >= logging.ERROR or is_user_action)


class _ApplicationWarningFileLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.name.startswith("client.") and record.levelno >= logging.WARNING


class _UserActionFileLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.name.startswith("client.") and bool(getattr(record, "user_action", False))


class _UpdateFileLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.name.startswith("client.system.updates")


def configure_logging(
    level: str,
    *,
    runtime_dir: Path | None = None,
    log_dir: Path | None = None,
) -> None:
    normalized_level = getattr(logging, level.upper(), logging.INFO)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    root_logger = logging.getLogger()

    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)
        handler.close()

    root_logger.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(normalized_level)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(_ApplicationLogFilter())
    root_logger.addHandler(console_handler)

    effective_log_dir = log_dir
    if effective_log_dir is None and runtime_dir is not None:
        effective_log_dir = runtime_dir / "logs"

    if effective_log_dir is None:
        return

    candidate_dirs = [effective_log_dir]
    fallback_log_dir = runtime_dir / "logs" if runtime_dir is not None else None
    if fallback_log_dir is not None and fallback_log_dir not in candidate_dirs:
        candidate_dirs.append(fallback_log_dir)

    for candidate_dir in candidate_dirs:
        try:
            candidate_dir.mkdir(parents=True, exist_ok=True)
            file_handler = RotatingFileHandler(
                candidate_dir / "eimzo-atb-client.log",
                maxBytes=_LOG_FILE_MAX_BYTES,
                backupCount=_LOG_FILE_BACKUP_COUNT,
                encoding="utf-8",
            )
            actions_handler = RotatingFileHandler(
                candidate_dir / "eimzo-atb-client-actions.log",
                maxBytes=_LOG_FILE_MAX_BYTES,
                backupCount=_LOG_FILE_BACKUP_COUNT,
                encoding="utf-8",
            )
            updates_handler = RotatingFileHandler(
                candidate_dir / "eimzo-atb-client-update.log",
                maxBytes=_LOG_FILE_MAX_BYTES,
                backupCount=_LOG_FILE_BACKUP_COUNT,
                encoding="utf-8",
            )
        except OSError as error:
            _LOGGER.warning("Could not initialize file logging in %s: %s", candidate_dir, error)
            continue

        file_handler.setLevel(logging.WARNING)
        file_handler.setFormatter(formatter)
        file_handler.addFilter(_ApplicationWarningFileLogFilter())
        root_logger.addHandler(file_handler)

        actions_handler.setLevel(logging.INFO)
        actions_handler.setFormatter(formatter)
        actions_handler.addFilter(_UserActionFileLogFilter())
        root_logger.addHandler(actions_handler)

        updates_handler.setLevel(logging.INFO)
        updates_handler.setFormatter(formatter)
        updates_handler.addFilter(_UpdateFileLogFilter())
        root_logger.addHandler(updates_handler)

        _LOGGER.info(
            "Application file logging is enabled at %s, %s and %s",
            candidate_dir / "eimzo-atb-client.log",
            candidate_dir / "eimzo-atb-client-actions.log",
            candidate_dir / "eimzo-atb-client-update.log",
        )
        return
