from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from urllib.parse import urlsplit

class ConfigurationError(RuntimeError):
    """Raised when required application configuration is missing or invalid."""


@dataclass(frozen=True, slots=True)
class AppConfig:
    api_eimzo_url: str
    ws_host: str
    ws_port: int
    ws_path: str
    server_retry_delay_seconds: float
    ws_ping_interval_seconds: float
    ws_ping_timeout_seconds: float
    http_timeout_seconds: float
    log_level: str
    runtime_dir: Path
    local_cert_valid_days: int
    local_cert_renew_before_days: int
    account_name_override: str | None = None

    @classmethod
    def from_env(cls) -> "AppConfig":
        api_eimzo_url = _require_env("API_EIMZO_URL").rstrip("/")
        return cls(
            api_eimzo_url=api_eimzo_url,
            ws_host=os.getenv("WS_SERVER_HOST", "127.0.0.1"),
            ws_port=_read_int("WS_SERVER_PORT", default=64443),
            ws_path=_normalize_ws_path(os.getenv("WS_SERVER_PATH", "/")),
            server_retry_delay_seconds=_read_float("WS_SERVER_RETRY_DELAY_SECONDS", default=5.0),
            ws_ping_interval_seconds=_read_float("WS_PING_INTERVAL_SECONDS", default=20.0),
            ws_ping_timeout_seconds=_read_float("WS_PING_TIMEOUT_SECONDS", default=20.0),
            http_timeout_seconds=_read_float("HTTP_TIMEOUT_SECONDS", default=60.0),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            runtime_dir=_build_runtime_dir(),
            local_cert_valid_days=_read_int("LOCAL_CERT_VALID_DAYS", default=365),
            local_cert_renew_before_days=_read_int("LOCAL_CERT_RENEW_BEFORE_DAYS", default=30),
            account_name_override=os.getenv("ACCOUNT_NAME_OVERRIDE"),
        )

    def use_local_api_ssl_certificate(self) -> bool:
        parsed = urlsplit(self.api_eimzo_url)
        return parsed.scheme == "https" and parsed.hostname in {"127.0.0.1", "localhost"}

    def websocket_bind_url(self) -> str:
        return f"wss://{self.ws_host}:{self.ws_port}{self.ws_path}"

    def matches_websocket_path(self, path: str | None) -> bool:
        if path in {None, ""}:
            path = "/"
        return path == self.ws_path


def _build_runtime_dir() -> Path:
    configured_path = os.getenv("APP_RUNTIME_DIR")
    if configured_path:
        return Path(configured_path)

    local_app_data = os.getenv("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "E-IMZO-ATB-Client"

    return Path.cwd() / ".runtime"


def _require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise ConfigurationError(f"{name} environment variable is required.")
    return value


def _read_float(name: str, *, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError as error:
        raise ConfigurationError(f"{name} must be a number, got {value!r}.") from error


def _read_int(name: str, *, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as error:
        raise ConfigurationError(f"{name} must be an integer, got {value!r}.") from error


def _normalize_ws_path(value: str) -> str:
    if not value:
        return "/"
    if not value.startswith("/"):
        return f"/{value}"
    return value
