from __future__ import annotations

from dataclasses import dataclass
import logging
import os
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from client.bootstrap.dotenv import load_dotenv
from client.bootstrap.settings import AppSettings, AppSettingsStore
from client.ui import prompt_api_base_url

LOGGER = logging.getLogger(__name__)


class ConfigurationError(RuntimeError):
    """Raised when required application configuration is missing or invalid."""


@dataclass(frozen=True, slots=True)
class AppConfig:
    api_eimzo_url: str
    api_eimzo_path_prefix: str
    api_eimzo_ca_cert_path: Path | None
    api_eimzo_send_account_header: bool
    log_dir: Path
    windows_auto_start_enabled: bool
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
    def from_env(
        cls,
        *,
        prompt_api_url: Callable[[str | None, str | None], str | None] | None = None,
    ) -> "AppConfig":
        load_dotenv()
        runtime_dir = _build_runtime_dir()
        settings_store = AppSettingsStore(runtime_dir)
        settings = settings_store.load()
        api_eimzo_url = _resolve_api_eimzo_url(
            runtime_dir=runtime_dir,
            settings=settings,
            settings_store=settings_store,
            prompt_api_url=prompt_api_url or _prompt_api_url,
        )
        config = cls(
            api_eimzo_url=api_eimzo_url,
            api_eimzo_path_prefix=_normalize_api_path_prefix(os.getenv("API_EIMZO_PATH_PREFIX", "")),
            api_eimzo_ca_cert_path=_read_optional_path("API_EIMZO_CA_CERT_PATH"),
            api_eimzo_send_account_header=_read_bool("API_EIMZO_SEND_ACCOUNT_HEADER", default=True),
            log_dir=_build_log_dir(runtime_dir),
            windows_auto_start_enabled=_read_bool("WINDOWS_AUTO_START", default=True),
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
            runtime_dir=runtime_dir,
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
        normalized_request_path = _normalize_request_path(path)
        normalized_configured_path = _normalize_request_path(self.ws_path)

        # When the server is configured for the root path, accept any incoming path.
        # This keeps the local bridge compatible with sites that hardcode legacy paths
        # such as /service/cryptapi while preserving strict matching for custom paths.
        if normalized_configured_path == "/":
            return True

        return normalized_request_path == normalized_configured_path

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


def _build_log_dir(runtime_dir: Path) -> Path:
    configured_path = os.getenv("APP_LOG_DIR")
    if configured_path:
        return Path(configured_path).expanduser()

    return runtime_dir / "logs"


def _resolve_api_eimzo_url(
    *,
    runtime_dir: Path,
    settings: AppSettings,
    settings_store: AppSettingsStore,
    prompt_api_url: Callable[[str | None, str | None], str | None],
) -> str:
    env_value = os.getenv("API_EIMZO_URL")
    if env_value:
        normalized_url = _normalize_api_base_url(env_value, source="API_EIMZO_URL")
        LOGGER.info("Using E-IMZO API URL from environment: %s", normalized_url)
        return normalized_url

    if settings.api_eimzo_url:
        try:
            normalized_url = _normalize_api_base_url(settings.api_eimzo_url, source="saved app settings")
            LOGGER.info("Using saved E-IMZO API URL from app settings: %s", normalized_url)
            return normalized_url
        except ConfigurationError:
            pass

    current_value = settings.api_eimzo_url
    error_message: str | None = None
    while True:
        prompt_value = prompt_api_url(current_value, error_message)
        if not prompt_value:
            raise ConfigurationError("API_EIMZO_URL is required.")

        try:
            normalized_url = _normalize_api_base_url(prompt_value, source="UI input")
        except ConfigurationError as error:
            current_value = prompt_value
            error_message = str(error)
            continue

        runtime_dir.mkdir(parents=True, exist_ok=True)
        settings_store.save(AppSettings(api_eimzo_url=normalized_url))
        LOGGER.info("Saved E-IMZO API URL from UI input to app settings: %s", normalized_url)
        return normalized_url


def _prompt_api_url(initial_value: str | None, error_message: str | None) -> str | None:
    return prompt_api_base_url(initial_value=initial_value, error_message=error_message)


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


def _normalize_api_path_prefix(value: str) -> str:
    if not value:
        return ""

    if not value.startswith("/"):
        value = f"/{value}"

    return value.rstrip("/")


def _normalize_api_base_url(value: str, *, source: str) -> str:
    normalized_value = value.strip().rstrip("/")
    if not normalized_value:
        raise ConfigurationError(f"{source} must not be empty.")

    parsed = urlparse(normalized_value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ConfigurationError(
            f"{source} must be a valid http(s) URL, got {value!r}."
        )

    return normalized_value


def _normalize_request_path(value: str | None) -> str:
    if value in {None, ""}:
        return "/"

    path = value.split("?", 1)[0].split("#", 1)[0]
    if not path.startswith("/"):
        path = f"/{path}"

    if len(path) > 1:
        path = path.rstrip("/")
        if not path:
            return "/"

    return path


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
