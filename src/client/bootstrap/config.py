from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path

from client.bootstrap.dotenv import load_dotenv


class ConfigurationError(RuntimeError):
    """Raised when required application configuration is missing or invalid."""


@dataclass(frozen=True, slots=True)
class AppConfig:
    api_eimzo_url: str
    api_eimzo_ca_cert_path: Path | None
    ws_host: str
    ws_port: int
    ws_path: str
    ws_server_cert_path: Path | None
    ws_server_key_path: Path | None
    local_cert_install_to_windows_root_store: bool
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
        load_dotenv()
        api_eimzo_url = _require_env("API_EIMZO_URL").rstrip("/")
        config = cls(
            api_eimzo_url=api_eimzo_url,
            api_eimzo_ca_cert_path=_read_optional_path("API_EIMZO_CA_CERT_PATH"),
            ws_host=os.getenv("WS_SERVER_HOST", "127.0.0.1"),
            ws_port=_read_int("WS_SERVER_PORT", default=64443),
            ws_path=_normalize_ws_path(os.getenv("WS_SERVER_PATH", "/")),
            ws_server_cert_path=_read_optional_path("WS_SERVER_CERT_PATH"),
            ws_server_key_path=_read_optional_path("WS_SERVER_KEY_PATH"),
            local_cert_install_to_windows_root_store=_read_bool(
                "LOCAL_CERT_INSTALL_TO_WINDOWS_ROOT_STORE",
                default=True,
            ),
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
        config._validate()
        return config

    def use_managed_server_certificate(self) -> bool:
        return self.ws_server_cert_path is None and self.ws_server_key_path is None

    def websocket_bind_url(self) -> str:
        return f"wss://{self.ws_host}:{self.ws_port}{self.ws_path}"

    def matches_websocket_path(self, path: str | None) -> bool:
        if path in {None, ""}:
            path = "/"
        return path == self.ws_path

    def _validate(self) -> None:
        if (self.ws_server_cert_path is None) != (self.ws_server_key_path is None):
            raise ConfigurationError(
                "WS_SERVER_CERT_PATH and WS_SERVER_KEY_PATH must be provided together."
            )

        _validate_optional_file(
            self.api_eimzo_ca_cert_path,
            name="API_EIMZO_CA_CERT_PATH",
        )
        _validate_optional_file(
            self.ws_server_cert_path,
            name="WS_SERVER_CERT_PATH",
        )
        _validate_optional_file(
            self.ws_server_key_path,
            name="WS_SERVER_KEY_PATH",
        )


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


def _read_bool(name: str, *, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default

    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False

    raise ConfigurationError(f"{name} must be a boolean, got {value!r}.")


def _normalize_ws_path(value: str) -> str:
    if not value:
        return "/"
    if not value.startswith("/"):
        return f"/{value}"
    return value


def _read_optional_path(name: str) -> Path | None:
    value = os.getenv(name)
    if not value:
        return None
    return Path(value).expanduser()


def _validate_optional_file(path: Path | None, *, name: str) -> None:
    if path is None:
        return
    if not path.exists():
        raise ConfigurationError(f"{name} file does not exist: {path}")
    if not path.is_file():
        raise ConfigurationError(f"{name} must point to a file, got: {path}")
